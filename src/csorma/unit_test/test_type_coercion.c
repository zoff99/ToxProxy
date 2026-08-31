/*
 * test_type_coercion.c — Tests for type coercion in result reading
 *
 * SQLite has dynamic typing with type affinity. A column declared
 * as INTEGER can hold a TEXT value and vice versa. The csorma
 * result reading functions (__rs_getLong, __rs_getString, __rs_getInt,
 * __rs_getBoolean) call sqlite3_column_* which will coerce types.
 *
 * These tests verify behavior when reading columns through
 * a "wrong" type accessor (e.g. reading TEXT via __rs_getLong).
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
    return db;
}

/* Helper: prepare, step, return the active statement */
static sqlite3_stmt *query_one(sqlite3 *db, const char *sql)
{
    sqlite3_stmt *st;
    sqlite3_prepare_v2(db, sql, -1, &st, 0);
    sqlite3_step(st);
    return st;
}

/* ============================================================
 *  Reading INTEGER columns via different accessors
 * ============================================================ */

static bool t_coerce_int_via_getstring(void)
{
    sqlite3 *db = open_mem();
    sqlite3_exec(db,
        "CREATE TABLE t(val INTEGER);"
        "INSERT INTO t VALUES(12345);",
        0, 0, 0);

    sqlite3_stmt *st = query_one(db, "SELECT val FROM t;");
    csorma_s *s = __rs_getString(st, "val");

    /* SQLite coerces 12345 → "12345" */
    T_ASSERT_PTR_NOT_NULL(s, "non-null");
    T_ASSERT_INT_EQ(s->l, 5, "len=5");
    T_ASSERT_STR_EQ((const char*)s->s, "12345", "int→text coercion");
    printf("         int→string: %.*s\n", s->l, s->s);

    csorma_str_free(s);
    sqlite3_finalize(st);
    sqlite3_close(db);
    return true;
}

static bool t_coerce_int_via_getboolean(void)
{
    sqlite3 *db = open_mem();
    sqlite3_exec(db,
        "CREATE TABLE t(val INTEGER);"
        "INSERT INTO t VALUES(42);",
        0, 0, 0);

    sqlite3_stmt *st = query_one(db, "SELECT val FROM t;");
    int8_t b = __rs_getBoolean(st, "val");

    /* 42 is non-zero → true */
    T_ASSERT_INT_EQ(b, 1, "42→true");
    printf("         int 42 → boolean: %d\n", b);

    sqlite3_finalize(st);
    sqlite3_close(db);
    return true;
}

static bool t_coerce_int_zero_via_getboolean(void)
{
    sqlite3 *db = open_mem();
    sqlite3_exec(db,
        "CREATE TABLE t(val INTEGER);"
        "INSERT INTO t VALUES(0);",
        0, 0, 0);

    sqlite3_stmt *st = query_one(db, "SELECT val FROM t;");
    int8_t b = __rs_getBoolean(st, "val");

    T_ASSERT_INT_EQ(b, 0, "0→false");
    printf("         int 0 → boolean: %d\n", b);

    sqlite3_finalize(st);
    sqlite3_close(db);
    return true;
}

static bool t_coerce_negative_int_via_getboolean(void)
{
    sqlite3 *db = open_mem();
    sqlite3_exec(db,
        "CREATE TABLE t(val INTEGER);"
        "INSERT INTO t VALUES(-1);",
        0, 0, 0);

    sqlite3_stmt *st = query_one(db, "SELECT val FROM t;");
    int8_t b = __rs_getBoolean(st, "val");

    /* -1 is non-zero → true */
    printf("         int -1 → boolean: %d\n", b);
    /* The result depends on how __rs_getBoolean handles the value */

    sqlite3_finalize(st);
    sqlite3_close(db);
    return true;
}

/* ============================================================
 *  Reading TEXT columns via different accessors
 * ============================================================ */

static bool t_coerce_text_numeric_via_getlong(void)
{
    sqlite3 *db = open_mem();
    sqlite3_exec(db,
        "CREATE TABLE t(val TEXT);"
        "INSERT INTO t VALUES('42');",
        0, 0, 0);

    sqlite3_stmt *st = query_one(db, "SELECT val FROM t;");
    int64_t v = __rs_getLong(st, "val");

    /* SQLite coerces "42" → 42 */
    T_ASSERT_INT_EQ(v, 42, "text '42' → long 42");
    printf("         text '42' → long: %lld\n", (long long)v);

    sqlite3_finalize(st);
    sqlite3_close(db);
    return true;
}

static bool t_coerce_text_nonnumeric_via_getlong(void)
{
    sqlite3 *db = open_mem();
    sqlite3_exec(db,
        "CREATE TABLE t(val TEXT);"
        "INSERT INTO t VALUES('hello');",
        0, 0, 0);

    sqlite3_stmt *st = query_one(db, "SELECT val FROM t;");
    int64_t v = __rs_getLong(st, "val");

    /* "hello" cannot be parsed as a number → 0 */
    T_ASSERT_INT_EQ(v, 0, "text 'hello' → long 0");
    printf("         text 'hello' → long: %lld\n", (long long)v);

    sqlite3_finalize(st);
    sqlite3_close(db);
    return true;
}

static bool t_coerce_text_mixed_via_getlong(void)
{
    sqlite3 *db = open_mem();
    sqlite3_exec(db,
        "CREATE TABLE t(val TEXT);"
        "INSERT INTO t VALUES('123abc');",
        0, 0, 0);

    sqlite3_stmt *st = query_one(db, "SELECT val FROM t;");
    int64_t v = __rs_getLong(st, "val");

    /* SQLite parses leading digits: "123abc" → 123 */
    printf("         text '123abc' → long: %lld\n", (long long)v);
    T_ASSERT_INT_EQ(v, 123, "leading digits parsed");

    sqlite3_finalize(st);
    sqlite3_close(db);
    return true;
}

static bool t_coerce_text_via_getint(void)
{
    sqlite3 *db = open_mem();
    sqlite3_exec(db,
        "CREATE TABLE t(val TEXT);"
        "INSERT INTO t VALUES('999');",
        0, 0, 0);

    sqlite3_stmt *st = query_one(db, "SELECT val FROM t;");
    int32_t v = __rs_getInt(st, "val");

    T_ASSERT_INT_EQ(v, 999, "text '999' → int 999");
    printf("         text '999' → int: %d\n", v);

    sqlite3_finalize(st);
    sqlite3_close(db);
    return true;
}

static bool t_coerce_text_via_getboolean(void)
{
    sqlite3 *db = open_mem();
    sqlite3_exec(db,
        "CREATE TABLE t(val TEXT);"
        "INSERT INTO t VALUES('1');",
        0, 0, 0);

    sqlite3_stmt *st = query_one(db, "SELECT val FROM t;");
    int8_t b = __rs_getBoolean(st, "val");

    /* "1" → 1 → true */
    printf("         text '1' → boolean: %d\n", b);
    T_ASSERT_INT_EQ(b, 1, "text '1' → true");

    sqlite3_finalize(st);
    sqlite3_close(db);
    return true;
}

static bool t_coerce_text_zero_via_getboolean(void)
{
    sqlite3 *db = open_mem();
    sqlite3_exec(db,
        "CREATE TABLE t(val TEXT);"
        "INSERT INTO t VALUES('0');",
        0, 0, 0);

    sqlite3_stmt *st = query_one(db, "SELECT val FROM t;");
    int8_t b = __rs_getBoolean(st, "val");

    printf("         text '0' → boolean: %d\n", b);
    T_ASSERT_INT_EQ(b, 0, "text '0' → false");

    sqlite3_finalize(st);
    sqlite3_close(db);
    return true;
}

static bool t_coerce_text_word_via_getboolean(void)
{
    sqlite3 *db = open_mem();
    sqlite3_exec(db,
        "CREATE TABLE t(val TEXT);"
        "INSERT INTO t VALUES('true');",
        0, 0, 0);

    sqlite3_stmt *st = query_one(db, "SELECT val FROM t;");
    int8_t b = __rs_getBoolean(st, "val");

    /* "true" is text, sqlite3_column_int returns 0 for non-numeric text */
    printf("         text 'true' → boolean: %d\n", b);
    T_ASSERT_INT_EQ(b, 0, "text 'true' → 0 (not parsed as boolean)");

    sqlite3_finalize(st);
    sqlite3_close(db);
    return true;
}

/* ============================================================
 *  Reading REAL (float) columns via different accessors
 * ============================================================ */

static bool t_coerce_real_via_getlong(void)
{
    sqlite3 *db = open_mem();
    sqlite3_exec(db,
        "CREATE TABLE t(val REAL);"
        "INSERT INTO t VALUES(3.14);",
        0, 0, 0);

    sqlite3_stmt *st = query_one(db, "SELECT val FROM t;");
    int64_t v = __rs_getLong(st, "val");

    /* 3.14 truncated to 3 */
    T_ASSERT_INT_EQ(v, 3, "real 3.14 → long 3 (truncated)");
    printf("         real 3.14 → long: %lld\n", (long long)v);

    sqlite3_finalize(st);
    sqlite3_close(db);
    return true;
}

static bool t_coerce_real_via_getint(void)
{
    sqlite3 *db = open_mem();
    sqlite3_exec(db,
        "CREATE TABLE t(val REAL);"
        "INSERT INTO t VALUES(99.9);",
        0, 0, 0);

    sqlite3_stmt *st = query_one(db, "SELECT val FROM t;");
    int32_t v = __rs_getInt(st, "val");

    T_ASSERT_INT_EQ(v, 99, "real 99.9 → int 99 (truncated)");
    printf("         real 99.9 → int: %d\n", v);

    sqlite3_finalize(st);
    sqlite3_close(db);
    return true;
}

static bool t_coerce_real_via_getstring(void)
{
    sqlite3 *db = open_mem();
    sqlite3_exec(db,
        "CREATE TABLE t(val REAL);"
        "INSERT INTO t VALUES(3.14);",
        0, 0, 0);

    sqlite3_stmt *st = query_one(db, "SELECT val FROM t;");
    csorma_s *s = __rs_getString(st, "val");

    T_ASSERT_PTR_NOT_NULL(s, "non-null");
    T_ASSERT(s->l > 0, "has content");
    printf("         real 3.14 → string: '%.*s'\n", s->l, s->s);

    csorma_str_free(s);
    sqlite3_finalize(st);
    sqlite3_close(db);
    return true;
}

static bool t_coerce_real_via_getboolean(void)
{
    sqlite3 *db = open_mem();
    sqlite3_exec(db,
        "CREATE TABLE t(val REAL);"
        "INSERT INTO t VALUES(0.0);",
        0, 0, 0);

    sqlite3_stmt *st = query_one(db, "SELECT val FROM t;");
    int8_t b = __rs_getBoolean(st, "val");

    printf("         real 0.0 → boolean: %d\n", b);
    T_ASSERT_INT_EQ(b, 0, "real 0.0 → false");

    sqlite3_finalize(st);
    sqlite3_close(db);
    return true;
}

/* ============================================================
 *  Reading NULL columns via different accessors
 * ============================================================ */

static bool t_coerce_null_via_getlong(void)
{
    sqlite3 *db = open_mem();
    sqlite3_exec(db,
        "CREATE TABLE t(val INTEGER);"
        "INSERT INTO t VALUES(NULL);",
        0, 0, 0);

    sqlite3_stmt *st = query_one(db, "SELECT val FROM t;");
    int64_t v = __rs_getLong(st, "val");

    /* NULL → 0 per sqlite3_column_int64 docs */
    T_ASSERT_INT_EQ(v, 0, "NULL → long 0");
    printf("         NULL → long: %lld\n", (long long)v);

    sqlite3_finalize(st);
    sqlite3_close(db);
    return true;
}

static bool t_coerce_null_via_getint(void)
{
    sqlite3 *db = open_mem();
    sqlite3_exec(db,
        "CREATE TABLE t(val INTEGER);"
        "INSERT INTO t VALUES(NULL);",
        0, 0, 0);

    sqlite3_stmt *st = query_one(db, "SELECT val FROM t;");
    int32_t v = __rs_getInt(st, "val");

    T_ASSERT_INT_EQ(v, 0, "NULL → int 0");

    sqlite3_finalize(st);
    sqlite3_close(db);
    return true;
}

static bool t_coerce_null_via_getboolean(void)
{
    sqlite3 *db = open_mem();
    sqlite3_exec(db,
        "CREATE TABLE t(val INTEGER);"
        "INSERT INTO t VALUES(NULL);",
        0, 0, 0);

    sqlite3_stmt *st = query_one(db, "SELECT val FROM t;");
    int8_t b = __rs_getBoolean(st, "val");

    T_ASSERT_INT_EQ(b, 0, "NULL → false");

    sqlite3_finalize(st);
    sqlite3_close(db);
    return true;
}

static bool t_coerce_null_via_getstring(void)
{
    sqlite3 *db = open_mem();
    sqlite3_exec(db,
        "CREATE TABLE t(val TEXT);"
        "INSERT INTO t VALUES(NULL);",
        0, 0, 0);

    sqlite3_stmt *st = query_one(db, "SELECT val FROM t;");
    csorma_s *s = __rs_getString(st, "val");

    /* __rs_getString should return empty string for NULL, not crash */
    T_ASSERT_PTR_NOT_NULL(s, "non-null struct");
    T_ASSERT_INT_EQ(s->l, 0, "empty for NULL");
    printf("         NULL → string len: %d\n", s->l);

    csorma_str_free(s);
    sqlite3_finalize(st);
    sqlite3_close(db);
    return true;
}

/* ============================================================
 *  Overflow / extreme value coercion
 * ============================================================ */

static bool t_coerce_huge_int_via_getint(void)
{
    sqlite3 *db = open_mem();
    sqlite3_exec(db,
        "CREATE TABLE t(val INTEGER);"
        "INSERT INTO t VALUES(9999999999999);",
        0, 0, 0);

    sqlite3_stmt *st = query_one(db, "SELECT val FROM t;");
    int32_t v = __rs_getInt(st, "val");

    /* 9999999999999 overflows int32 — truncation */
    printf("         9999999999999 → int32: %d (truncated)\n", v);

    sqlite3_finalize(st);
    sqlite3_close(db);
    return true;
}

static bool t_coerce_huge_int_via_getlong(void)
{
    sqlite3 *db = open_mem();
    sqlite3_exec(db,
        "CREATE TABLE t(val INTEGER);"
        "INSERT INTO t VALUES(9999999999999);",
        0, 0, 0);

    sqlite3_stmt *st = query_one(db, "SELECT val FROM t;");
    int64_t v = __rs_getLong(st, "val");

    /* Fits in int64 */
    T_ASSERT_INT_EQ(v, 9999999999999LL, "large int preserved in int64");

    sqlite3_finalize(st);
    sqlite3_close(db);
    return true;
}

/* ============================================================
 *  MAIN
 * ============================================================ */
int main(void)
{
    printf(C_BOLD "\n");
    printf("  ================================================================\n");
    printf("   CSORMA TYPE COERCION TESTS\n");
    printf("   Source: ../template/csorma.c (compiled directly)\n");
    printf("  ================================================================\n");
    printf(C_RESET "\n");

    TEST_SUITE("INTEGER via wrong accessor");
    RUN_TEST(t_coerce_int_via_getstring);
    RUN_TEST(t_coerce_int_via_getboolean);
    RUN_TEST(t_coerce_int_zero_via_getboolean);
    RUN_TEST(t_coerce_negative_int_via_getboolean);
    SUITE_END();

    TEST_SUITE("TEXT via wrong accessor");
    RUN_TEST(t_coerce_text_numeric_via_getlong);
    RUN_TEST(t_coerce_text_nonnumeric_via_getlong);
    RUN_TEST(t_coerce_text_mixed_via_getlong);
    RUN_TEST(t_coerce_text_via_getint);
    RUN_TEST(t_coerce_text_via_getboolean);
    RUN_TEST(t_coerce_text_zero_via_getboolean);
    RUN_TEST(t_coerce_text_word_via_getboolean);
    SUITE_END();

    TEST_SUITE("REAL via wrong accessor");
    RUN_TEST(t_coerce_real_via_getlong);
    RUN_TEST(t_coerce_real_via_getint);
    RUN_TEST(t_coerce_real_via_getstring);
    RUN_TEST(t_coerce_real_via_getboolean);
    SUITE_END();

    TEST_SUITE("NULL via all accessors");
    RUN_TEST(t_coerce_null_via_getlong);
    RUN_TEST(t_coerce_null_via_getint);
    RUN_TEST(t_coerce_null_via_getboolean);
    RUN_TEST(t_coerce_null_via_getstring);
    SUITE_END();

    TEST_SUITE("Overflow coercion");
    RUN_TEST(t_coerce_huge_int_via_getint);
    RUN_TEST(t_coerce_huge_int_via_getlong);
    SUITE_END();

    return test_summary("Type Coercion");
}

