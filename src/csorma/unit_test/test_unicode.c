/*
 * test_unicode.c — Tests for Unicode and special characters in data
 *
 * csorma's README claims:
 *   "safe Strings (UTF-8 or even broken UTF-8 or just random bytes)"
 *
 * These tests verify that claim by passing Unicode, special characters,
 * and edge-case strings through the full bind → store → read path.
 */

#include "test_framework.h"
#include "csorma.h"
#include "sqlite3.h"

/* ============================================================
 *  Helpers
 * ============================================================ */

static sqlite3 *open_mem(void)
{
    sqlite3 *db;
    sqlite3_open(":memory:", &db);
    sqlite3_exec(db, "CREATE TABLE t(val TEXT);", 0, 0, 0);
    return db;
}

/* Helper: store a string via bind, read it back, verify */
static bool store_and_verify(const char *test_name, const char *data, uint32_t data_len)
{
    sqlite3 *db = open_mem();

    /* Store via bindvar_to_stmt */
    sqlite3_stmt *stmt;
    sqlite3_prepare_v2(db, "INSERT INTO t VALUES(?1);", -1, &stmt, 0);
    csorma_s *str = csorma_str_build(data, data_len);
    bindvar_to_stmt(stmt, 1, BINDVAR_TYPE_String, 0, 0, str);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    /* Read back */
    sqlite3_stmt *sel;
    sqlite3_prepare_v2(db, "SELECT val FROM t;", -1, &sel, 0);
    sqlite3_step(sel);
    int read_len = sqlite3_column_bytes(sel, 0);
    const unsigned char *read_data = sqlite3_column_text(sel, 0);

    bool ok = true;
    if ((uint32_t)read_len != data_len)
    {
        printf("         [%s] length mismatch: expected %u, got %d\n",
               test_name, data_len, read_len);
        ok = false;
    }
    else if (memcmp(read_data, data, data_len) != 0)
    {
        printf("         [%s] content mismatch\n", test_name);
        ok = false;
    }

    sqlite3_finalize(sel);
    csorma_str_free(str);
    sqlite3_close(db);
    return ok;
}

/* ============================================================
 *  UTF-8 multibyte strings
 * ============================================================ */

static bool t_utf8_ascii(void)
{
    const char *data = "hello world";
    bool ok = store_and_verify("ascii", data, strlen(data));
    T_ASSERT(ok, "ASCII round-trip");
    return true;
}

static bool t_utf8_2byte(void)
{
    /* Latin extended: é è ê ë */
    const char *data = "caf\xc3\xa9 r\xc3\xa9sum\xc3\xa9";
    bool ok = store_and_verify("2-byte UTF-8", data, strlen(data));
    T_ASSERT(ok, "2-byte UTF-8 round-trip");
    return true;
}

static bool t_utf8_3byte_chinese(void)
{
    /* Chinese: 你好世界 (hello world) */
    const char *data = "\xe4\xbd\xa0\xe5\xa5\xbd\xe4\xb8\x96\xe7\x95\x8c";
    bool ok = store_and_verify("Chinese", data, strlen(data));
    T_ASSERT(ok, "Chinese round-trip");
    return true;
}

static bool t_utf8_3byte_japanese(void)
{
    /* Japanese: こんにちは */
    const char *data = "\xe3\x81\x93\xe3\x82\x93\xe3\x81\xab\xe3\x81\xa1\xe3\x81\xaf";
    bool ok = store_and_verify("Japanese", data, strlen(data));
    T_ASSERT(ok, "Japanese round-trip");
    return true;
}

static bool t_utf8_4byte_emoji(void)
{
    /* Emoji: 😀🎉🚀 */
    const char *data = "\xf0\x9f\x98\x80\xf0\x9f\x8e\x89\xf0\x9f\x9a\x80";
    bool ok = store_and_verify("Emoji", data, strlen(data));
    T_ASSERT(ok, "Emoji round-trip");
    return true;
}

static bool t_utf8_mixed(void)
{
    /* Mixed: ASCII + Chinese + Emoji */
    const char *data = "Hello \xe4\xb8\x96\xe7\x95\x8c \xf0\x9f\x8c\x8d!";
    bool ok = store_and_verify("Mixed", data, strlen(data));
    T_ASSERT(ok, "Mixed UTF-8 round-trip");
    return true;
}

static bool t_utf8_large(void)
{
    /* 10000 emoji (4 bytes each = 40KB) */
    csorma_s *big = csorma_str2_build("");
    for (int i = 0; i < 10000; i++)
    {
        big = csorma_str_con(big, "\xf0\x9f\x98\x80", 4);
    }

    sqlite3 *db = open_mem();
    sqlite3_stmt *stmt;
    sqlite3_prepare_v2(db, "INSERT INTO t VALUES(?1);", -1, &stmt, 0);
    bindvar_to_stmt(stmt, 1, BINDVAR_TYPE_String, 0, 0, big);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    sqlite3_stmt *sel;
    sqlite3_prepare_v2(db, "SELECT val FROM t;", -1, &sel, 0);
    sqlite3_step(sel);
    int read_len = sqlite3_column_bytes(sel, 0);
    T_ASSERT_INT_EQ(read_len, 40000, "40KB of emoji preserved");

    sqlite3_finalize(sel);
    csorma_str_free(big);
    sqlite3_close(db);
    return true;
}

/* ============================================================
 *  Broken / invalid UTF-8
 * ============================================================ */

static bool t_broken_utf8_lone_continuation(void)
{
    /* Lone continuation byte (invalid UTF-8) */
    const char data[] = {'\x80', '\x81', '\x82'};
    bool ok = store_and_verify("lone continuation", data, 3);
    T_ASSERT(ok, "broken UTF-8 preserved as raw bytes");
    return true;
}

static bool t_broken_utf8_truncated(void)
{
    /* Truncated 3-byte sequence: only 2 of 3 bytes */
    const char data[] = {'\xe4', '\xbd'};
    bool ok = store_and_verify("truncated sequence", data, 2);
    T_ASSERT(ok, "truncated UTF-8 preserved");
    return true;
}

static bool t_broken_utf8_overlong(void)
{
    /* Overlong encoding of NUL (invalid) */
    const char data[] = {'\xc0', '\x80'};
    bool ok = store_and_verify("overlong NUL", data, 2);
    T_ASSERT(ok, "overlong encoding preserved");
    return true;
}

static bool t_broken_utf8_fe_ff(void)
{
    /* 0xFE and 0xFF are never valid in UTF-8 */
    const char data[] = {'\xfe', '\xff', '\xfe'};
    bool ok = store_and_verify("0xFE 0xFF", data, 3);
    T_ASSERT(ok, "invalid bytes preserved");
    return true;
}

/* ============================================================
 *  SQL special characters
 * ============================================================ */

static bool t_special_single_quote(void)
{
    const char *data = "it's a test";
    bool ok = store_and_verify("single quote", data, strlen(data));
    T_ASSERT(ok, "single quote preserved");
    return true;
}

static bool t_special_double_quote(void)
{
    const char *data = "say \"hello\"";
    bool ok = store_and_verify("double quote", data, strlen(data));
    T_ASSERT(ok, "double quote preserved");
    return true;
}

static bool t_special_both_quotes(void)
{
    const char *data = "it's \"quoted\"";
    bool ok = store_and_verify("both quotes", data, strlen(data));
    T_ASSERT(ok, "both quotes preserved");
    return true;
}

static bool t_special_sql_injection_chars(void)
{
    /* Characters commonly used in SQL injection */
    const char *data = "'; DROP TABLE t; --";
    bool ok = store_and_verify("injection chars", data, strlen(data));
    T_ASSERT(ok, "injection chars stored as literal");
    return true;
}

static bool t_special_backslash(void)
{
    const char *data = "path\\to\\file";
    bool ok = store_and_verify("backslash", data, strlen(data));
    T_ASSERT(ok, "backslash preserved");
    return true;
}

static bool t_special_percent_underscore(void)
{
    /* LIKE wildcards */
    const char *data = "100% _wildcard_";
    bool ok = store_and_verify("LIKE wildcards", data, strlen(data));
    T_ASSERT(ok, "LIKE wildcards preserved");
    return true;
}

/* ============================================================
 *  Control characters
 * ============================================================ */

static bool t_control_newline(void)
{
    const char *data = "line1\nline2\nline3";
    bool ok = store_and_verify("newline", data, strlen(data));
    T_ASSERT(ok, "newline preserved");
    return true;
}

static bool t_control_tab(void)
{
    const char *data = "col1\tcol2\tcol3";
    bool ok = store_and_verify("tab", data, strlen(data));
    T_ASSERT(ok, "tab preserved");
    return true;
}

static bool t_control_carriage_return(void)
{
    const char *data = "line1\r\nline2\r\n";
    bool ok = store_and_verify("CRLF", data, strlen(data));
    T_ASSERT(ok, "CRLF preserved");
    return true;
}

static bool t_control_all_low(void)
{
    /* All control characters 0x01-0x1F (excluding NUL which is separate) */
    char data[31];
    for (int i = 0; i < 31; i++)
        data[i] = (char)(i + 1);
    bool ok = store_and_verify("control chars", data, 31);
    T_ASSERT(ok, "control chars preserved");
    return true;
}

/* ============================================================
 *  NUL bytes (binary data)
 * ============================================================ */

static bool t_nul_single(void)
{
    const char data[] = {'a', '\0', 'b'};
    bool ok = store_and_verify("single NUL", data, 3);
    T_ASSERT(ok, "single NUL preserved");
    return true;
}

static bool t_nul_multiple(void)
{
    const char data[] = {'\0', '\0', '\0', '\0', '\0'};
    bool ok = store_and_verify("all NUL", data, 5);
    T_ASSERT(ok, "all-NUL preserved");
    return true;
}

static bool t_nul_at_start(void)
{
    const char data[] = {'\0', 'h', 'i'};
    bool ok = store_and_verify("NUL at start", data, 3);
    T_ASSERT(ok, "NUL at start preserved");
    return true;
}

static bool t_nul_at_end(void)
{
    const char data[] = {'h', 'i', '\0'};
    bool ok = store_and_verify("NUL at end", data, 3);
    T_ASSERT(ok, "NUL at end preserved");
    return true;
}

/* ============================================================
 *  Random binary data
 * ============================================================ */

static bool t_random_binary(void)
{
    /* All 256 byte values */
    char data[256];
    for (int i = 0; i < 256; i++)
        data[i] = (char)i;
    bool ok = store_and_verify("all 256 bytes", data, 256);
    T_ASSERT(ok, "all byte values preserved");
    return true;
}

static bool t_random_large_binary(void)
{
    /* 10KB of pseudo-random data */
    csorma_s *big = csorma_str2_build("");
    unsigned int seed = 12345;
    for (int i = 0; i < 10000; i++)
    {
        seed = seed * 1103515245 + 12345;
        char byte = (char)((seed >> 16) & 0xFF);
        big = csorma_str_con(big, &byte, 1);
    }

    sqlite3 *db = open_mem();
    sqlite3_stmt *stmt;
    sqlite3_prepare_v2(db, "INSERT INTO t VALUES(?1);", -1, &stmt, 0);
    bindvar_to_stmt(stmt, 1, BINDVAR_TYPE_String, 0, 0, big);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    sqlite3_stmt *sel;
    sqlite3_prepare_v2(db, "SELECT val FROM t;", -1, &sel, 0);
    sqlite3_step(sel);
    int read_len = sqlite3_column_bytes(sel, 0);
    T_ASSERT_INT_EQ(read_len, 10000, "10KB binary preserved");

    /* Verify first few bytes match the sequence */
    const unsigned char *read_data = sqlite3_column_text(sel, 0);
    T_ASSERT_MEM_EQ(read_data, big->s, 100, "first 100 bytes match");

    sqlite3_finalize(sel);
    csorma_str_free(big);
    sqlite3_close(db);
    return true;
}

/* ============================================================
 *  Unicode through the full ORM path (bind_all_where_bindvars)
 * ============================================================ */

static bool t_unicode_in_where_clause(void)
{
    sqlite3 *db;
    sqlite3_open(":memory:", &db);
    sqlite3_exec(db,
        "CREATE TABLE t(name TEXT, value INTEGER);"
        "INSERT INTO t VALUES('\xe4\xbd\xa0\xe5\xa5\xbd', 100);"  /* 你好 */
        "INSERT INTO t VALUES('hello', 200);",
        0, 0, 0);

    /* Query with Unicode in WHERE clause via bind variable */
    OrmaBindvars *bv = bindvar_init(NULL);
    csorma_s *search = csorma_str2_build("\xe4\xbd\xa0\xe5\xa5\xbd"); /* 你好 */
    bv = bindvar_add_s(bv, search);

    sqlite3_stmt *stmt;
    sqlite3_prepare_v2(db, "SELECT value FROM t WHERE name = ?400;", -1, &stmt, 0);
    bind_all_where_bindvars(stmt, bv);

    int rc = sqlite3_step(stmt);
    T_ASSERT_INT_EQ(rc, SQLITE_ROW, "found row");
    T_ASSERT_INT_EQ(sqlite3_column_int(stmt, 0), 100, "Unicode WHERE matched");

    sqlite3_finalize(stmt);
    bindvar_free(bv);
    sqlite3_close(db);
    return true;
}

static bool t_unicode_in_set_clause(void)
{
    sqlite3 *db;
    sqlite3_open(":memory:", &db);
    sqlite3_exec(db,
        "CREATE TABLE t(name TEXT);"
        "INSERT INTO t VALUES('old');",
        0, 0, 0);

    /* UPDATE with Unicode via bind variable */
    OrmaBindvars *bv = bindvar_init(NULL);
    csorma_s *newval = csorma_str2_build("\xf0\x9f\x8e\x89\xf0\x9f\x9a\x80"); /* 🎉🚀 */
    bv = bindvar_add_s(bv, newval);

    sqlite3_stmt *stmt;
    sqlite3_prepare_v2(db, "UPDATE t SET name = ?600;", -1, &stmt, 0);
    bind_all_set_bindvars(stmt, bv);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    /* Verify */
    sqlite3_stmt *sel;
    sqlite3_prepare_v2(db, "SELECT name FROM t;", -1, &sel, 0);
    sqlite3_step(sel);
    const char *val = (const char *)sqlite3_column_text(sel, 0);
    T_ASSERT_STR_EQ(val, "\xf0\x9f\x8e\x89\xf0\x9f\x9a\x80", "Unicode SET worked");

    sqlite3_finalize(sel);
    bindvar_free(bv);
    sqlite3_close(db);
    return true;
}

/* ============================================================
 *  Empty string (distinct from NULL)
 * ============================================================ */

static bool t_empty_string(void)
{
    const char *data = "";
    bool ok = store_and_verify("empty", data, 0);
    T_ASSERT(ok, "empty string preserved");
    return true;
}

/* ============================================================
 *  MAIN
 * ============================================================ */
int main(void)
{
    printf(C_BOLD "\n");
    printf("  ================================================================\n");
    printf("   CSORMA UNICODE & SPECIAL CHARACTER TESTS\n");
    printf("   Source: ../template/csorma.c (compiled directly)\n");
    printf("   Verifies: \"safe Strings (UTF-8 or even broken UTF-8\n");
    printf("             or just random bytes)\" — README claim\n");
    printf("  ================================================================\n");
    printf(C_RESET "\n");

    TEST_SUITE("UTF-8 multibyte");
    RUN_TEST(t_utf8_ascii);
    RUN_TEST(t_utf8_2byte);
    RUN_TEST(t_utf8_3byte_chinese);
    RUN_TEST(t_utf8_3byte_japanese);
    RUN_TEST(t_utf8_4byte_emoji);
    RUN_TEST(t_utf8_mixed);
    RUN_TEST(t_utf8_large);
    SUITE_END();

    TEST_SUITE("Broken / invalid UTF-8");
    RUN_TEST(t_broken_utf8_lone_continuation);
    RUN_TEST(t_broken_utf8_truncated);
    RUN_TEST(t_broken_utf8_overlong);
    RUN_TEST(t_broken_utf8_fe_ff);
    SUITE_END();

    TEST_SUITE("SQL special characters");
    RUN_TEST(t_special_single_quote);
    RUN_TEST(t_special_double_quote);
    RUN_TEST(t_special_both_quotes);
    RUN_TEST(t_special_sql_injection_chars);
    RUN_TEST(t_special_backslash);
    RUN_TEST(t_special_percent_underscore);
    SUITE_END();

    TEST_SUITE("Control characters");
    RUN_TEST(t_control_newline);
    RUN_TEST(t_control_tab);
    RUN_TEST(t_control_carriage_return);
    RUN_TEST(t_control_all_low);
    SUITE_END();

    TEST_SUITE("NUL bytes");
    RUN_TEST(t_nul_single);
    RUN_TEST(t_nul_multiple);
    RUN_TEST(t_nul_at_start);
    RUN_TEST(t_nul_at_end);
    SUITE_END();

    TEST_SUITE("Random binary");
    RUN_TEST(t_random_binary);
    RUN_TEST(t_random_large_binary);
    SUITE_END();

    TEST_SUITE("Unicode through ORM bind path");
    RUN_TEST(t_unicode_in_where_clause);
    RUN_TEST(t_unicode_in_set_clause);
    SUITE_END();

    TEST_SUITE("Empty string");
    RUN_TEST(t_empty_string);
    SUITE_END();

    return test_summary("Unicode & Special Characters");
}
