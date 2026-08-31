/*
 * test_bind_lifetime.c — Tests for SQLITE_STATIC binding lifetime safety
 *
 * csorma binds strings with SQLITE_STATIC:
 *
 *   sqlite3_bind_text(stmt, idx, str->s, str->l, SQLITE_STATIC);
 *
 * SQLITE_STATIC tells SQLite the buffer will remain valid until the
 * statement is finalized or rebound. If the buffer is freed before
 * sqlite3_step() is called, the bind points to freed memory →
 * use-after-free.
 *
 * These tests verify the correct ordering of operations.
 * Run under ASAN for maximum detection:
 *   make asan_all
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

/* ============================================================
 *  TEST 1: Correct lifetime — bind, execute, then free
 *
 *  This is the CORRECT usage pattern. The string stays alive
 *  until after sqlite3_step completes.
 * ============================================================ */

static bool t_lifetime_correct_order(void)
{
    sqlite3 *db = open_mem();
    sqlite3_exec(db, "CREATE TABLE t(val TEXT);", 0, 0, 0);

    sqlite3_stmt *stmt;
    sqlite3_prepare_v2(db, "INSERT INTO t VALUES(?1);", -1, &stmt, 0);

    csorma_s *str = csorma_str2_build("correct_order");
    bindvar_to_stmt(stmt, 1, BINDVAR_TYPE_String, 0, 0, str);

    /* Execute WHILE string is still alive — correct */
    int rc = sqlite3_step(stmt);
    T_ASSERT_INT_EQ(rc, SQLITE_DONE, "insert ok");
    sqlite3_finalize(stmt);

    /* NOW free the string — safe, statement is finalized */
    csorma_str_free(str);

    /* Verify data */
    sqlite3_stmt *sel;
    sqlite3_prepare_v2(db, "SELECT val FROM t;", -1, &sel, 0);
    sqlite3_step(sel);
    T_ASSERT_STR_EQ((const char*)sqlite3_column_text(sel, 0),
                    "correct_order", "content intact");
    sqlite3_finalize(sel);
    sqlite3_close(db);
    return true;
}

/* ============================================================
 *  TEST 2: Bind, execute, finalize, then free — also correct
 * ============================================================ */

static bool t_lifetime_finalize_then_free(void)
{
    sqlite3 *db = open_mem();
    sqlite3_exec(db, "CREATE TABLE t(val TEXT);", 0, 0, 0);

    sqlite3_stmt *stmt;
    sqlite3_prepare_v2(db, "INSERT INTO t VALUES(?1);", -1, &stmt, 0);

    csorma_s *str = csorma_str2_build("finalize_first");
    bindvar_to_stmt(stmt, 1, BINDVAR_TYPE_String, 0, 0, str);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);  /* finalize first */
    csorma_str_free(str);    /* then free — safe */

    sqlite3_stmt *sel;
    sqlite3_prepare_v2(db, "SELECT val FROM t;", -1, &sel, 0);
    sqlite3_step(sel);
    T_ASSERT_STR_EQ((const char*)sqlite3_column_text(sel, 0),
                    "finalize_first", "content");
    sqlite3_finalize(sel);
    sqlite3_close(db);
    return true;
}

/* ============================================================
 *  TEST 3: Multiple binds on same statement — each must be
 *           alive at the time of execution
 * ============================================================ */

static bool t_lifetime_multiple_binds(void)
{
    sqlite3 *db = open_mem();
    sqlite3_exec(db, "CREATE TABLE t(a TEXT, b TEXT);", 0, 0, 0);

    sqlite3_stmt *stmt;
    sqlite3_prepare_v2(db, "INSERT INTO t VALUES(?1, ?2);", -1, &stmt, 0);

    csorma_s *s1 = csorma_str2_build("first");
    csorma_s *s2 = csorma_str2_build("second");
    bindvar_to_stmt(stmt, 1, BINDVAR_TYPE_String, 0, 0, s1);
    bindvar_to_stmt(stmt, 2, BINDVAR_TYPE_String, 0, 0, s2);

    /* Both strings alive during step — correct */
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    csorma_str_free(s1);
    csorma_str_free(s2);

    sqlite3_stmt *sel;
    sqlite3_prepare_v2(db, "SELECT a, b FROM t;", -1, &sel, 0);
    sqlite3_step(sel);
    T_ASSERT_STR_EQ((const char*)sqlite3_column_text(sel, 0), "first", "a");
    T_ASSERT_STR_EQ((const char*)sqlite3_column_text(sel, 1), "second", "b");
    sqlite3_finalize(sel);
    sqlite3_close(db);
    return true;
}

/* ============================================================
 *  TEST 4: Bind via bind_all_where_bindvars — verify string
 *           stays alive through execution
 * ============================================================ */

static bool t_lifetime_where_bindvars(void)
{
    sqlite3 *db = open_mem();
    sqlite3_exec(db,
        "CREATE TABLE t(name TEXT, score INTEGER);"
        "INSERT INTO t VALUES('alice', 100);"
        "INSERT INTO t VALUES('bob', 200);",
        0, 0, 0);

    OrmaBindvars *bv = bindvar_init(NULL);
    csorma_s *name = csorma_str2_build("alice");
    bv = bindvar_add_s(bv, name);

    sqlite3_stmt *stmt;
    sqlite3_prepare_v2(db,
        "SELECT score FROM t WHERE name = ?400;", -1, &stmt, 0);
    bind_all_where_bindvars(stmt, bv);

    /* name is still alive here — correct */
    int rc = sqlite3_step(stmt);
    T_ASSERT_INT_EQ(rc, SQLITE_ROW, "got row");
    T_ASSERT_INT_EQ(sqlite3_column_int(stmt, 0), 100, "alice's score");

    sqlite3_finalize(stmt);
    bindvar_free(bv);  /* frees name via bindvar's ownership */
    sqlite3_close(db);
    return true;
}

/* ============================================================
 *  TEST 5: Bind via bind_all_set_bindvars — verify string
 *           stays alive through execution
 * ============================================================ */

static bool t_lifetime_set_bindvars(void)
{
    sqlite3 *db = open_mem();
    sqlite3_exec(db,
        "CREATE TABLE t(name TEXT);"
        "INSERT INTO t VALUES('old');",
        0, 0, 0);

    OrmaBindvars *bv = bindvar_init(NULL);
    csorma_s *newname = csorma_str2_build("updated_name");
    bv = bindvar_add_s(bv, newname);

    sqlite3_stmt *stmt;
    sqlite3_prepare_v2(db,
        "UPDATE t SET name = ?600;", -1, &stmt, 0);
    bind_all_set_bindvars(stmt, bv);

    /* newname still alive — correct */
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    /* Verify */
    sqlite3_stmt *sel;
    sqlite3_prepare_v2(db, "SELECT name FROM t;", -1, &sel, 0);
    sqlite3_step(sel);
    T_ASSERT_STR_EQ((const char*)sqlite3_column_text(sel, 0),
                    "updated_name", "updated");
    sqlite3_finalize(sel);

    bindvar_free(bv);
    sqlite3_close(db);
    return true;
}

/* ============================================================
 *  TEST 6: Rebind same statement with new value
 *
 *  After sqlite3_reset(), the statement can be rebound.
 *  The OLD string can be freed after reset, and a NEW string
 *  bound before the next step.
 * ============================================================ */

static bool t_lifetime_rebind_after_reset(void)
{
    sqlite3 *db = open_mem();
    sqlite3_exec(db, "CREATE TABLE t(val TEXT);", 0, 0, 0);

    sqlite3_stmt *stmt;
    sqlite3_prepare_v2(db, "INSERT INTO t VALUES(?1);", -1, &stmt, 0);

    /* First bind + execute */
    csorma_s *s1 = csorma_str2_build("value_1");
    bindvar_to_stmt(stmt, 1, BINDVAR_TYPE_String, 0, 0, s1);
    sqlite3_step(stmt);
    sqlite3_reset(stmt);
    /* After reset, s1 is no longer needed by the statement */
    csorma_str_free(s1);

    /* Second bind + execute */
    csorma_s *s2 = csorma_str2_build("value_2");
    bindvar_to_stmt(stmt, 1, BINDVAR_TYPE_String, 0, 0, s2);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    csorma_str_free(s2);

    /* Verify both rows */
    sqlite3_stmt *sel;
    sqlite3_prepare_v2(db, "SELECT val FROM t ORDER BY rowid;", -1, &sel, 0);
    sqlite3_step(sel);
    T_ASSERT_STR_EQ((const char*)sqlite3_column_text(sel, 0), "value_1", "first");
    sqlite3_step(sel);
    T_ASSERT_STR_EQ((const char*)sqlite3_column_text(sel, 0), "value_2", "second");
    sqlite3_finalize(sel);
    sqlite3_close(db);
    return true;
}

/* ============================================================
 *  TEST 7: Large string binding — verify no truncation
 * ============================================================ */

static bool t_lifetime_large_string(void)
{
    sqlite3 *db = open_mem();
    sqlite3_exec(db, "CREATE TABLE t(val TEXT);", 0, 0, 0);

    /* Build a ~49KB string (1000 chunks × 49 chars each) */
    csorma_s *big = csorma_str2_build("");
    for (int i = 0; i < 1000; i++)
    {
        char chunk[128];
        int len = snprintf(chunk, sizeof(chunk),
            "chunk_%04d_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA_", i);
        big = csorma_str_con(big, chunk, (uint32_t)len);
    }
    uint32_t original_len = big->l;
    T_ASSERT(original_len > 40000, "large string built (~49KB)");
    printf("         built string length: %u bytes\n", original_len);

    sqlite3_stmt *stmt;
    sqlite3_prepare_v2(db, "INSERT INTO t VALUES(?1);", -1, &stmt, 0);
    bindvar_to_stmt(stmt, 1, BINDVAR_TYPE_String, 0, 0, big);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    /* Read back and verify full length preserved */
    sqlite3_stmt *sel;
    sqlite3_prepare_v2(db, "SELECT val FROM t;", -1, &sel, 0);
    sqlite3_step(sel);
    int readback_len = sqlite3_column_bytes(sel, 0);
    T_ASSERT_INT_EQ((uint32_t)readback_len, original_len, "full length preserved");

    /* Verify prefix and suffix */
    const char *val = (const char *)sqlite3_column_text(sel, 0);
    T_ASSERT(memcmp(val, "chunk_0000_", 11) == 0, "prefix intact");
    T_ASSERT(memcmp(val + readback_len - 1, "_", 1) == 0, "suffix intact");

    printf("         large string binding: round-trip OK (%u bytes)\n", original_len);

    sqlite3_finalize(sel);
    csorma_str_free(big);
    sqlite3_close(db);
    return true;
}

/* ============================================================
 *  TEST 8: Empty string binding
 * ============================================================ */

static bool t_lifetime_empty_string(void)
{
    sqlite3 *db = open_mem();
    sqlite3_exec(db, "CREATE TABLE t(val TEXT);", 0, 0, 0);

    sqlite3_stmt *stmt;
    sqlite3_prepare_v2(db, "INSERT INTO t VALUES(?1);", -1, &stmt, 0);

    csorma_s *empty = csorma_str2_build("");
    bindvar_to_stmt(stmt, 1, BINDVAR_TYPE_String, 0, 0, empty);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    /* Verify: empty string is NOT the same as NULL */
    sqlite3_stmt *sel;
    sqlite3_prepare_v2(db, "SELECT val, typeof(val) FROM t;", -1, &sel, 0);
    sqlite3_step(sel);
    T_ASSERT_INT_EQ(sqlite3_column_type(sel, 0), SQLITE_TEXT, "type is TEXT not NULL");
    T_ASSERT_INT_EQ(sqlite3_column_bytes(sel, 0), 0, "length is 0");
    T_ASSERT_STR_EQ((const char*)sqlite3_column_text(sel, 0), "", "empty string");

    sqlite3_finalize(sel);
    csorma_str_free(empty);
    sqlite3_close(db);
    return true;
}

/* ============================================================
 *  TEST 9: String with SQL injection attempt — SQLITE_STATIC
 *           ensures the data is treated as a literal value,
 *           never as SQL
 * ============================================================ */

static bool t_lifetime_injection_in_bound_string(void)
{
    sqlite3 *db = open_mem();
    sqlite3_exec(db,
        "CREATE TABLE t(val TEXT);"
        "CREATE TABLE secret(data TEXT);"
        "INSERT INTO secret VALUES('top_secret');",
        0, 0, 0);

    sqlite3_stmt *stmt;
    sqlite3_prepare_v2(db, "INSERT INTO t VALUES(?1);", -1, &stmt, 0);

    /* Attempt SQL injection via bound parameter */
    csorma_s *injection = csorma_str2_build("'); DROP TABLE secret; --");
    bindvar_to_stmt(stmt, 1, BINDVAR_TYPE_String, 0, 0, injection);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    /* Verify: the injection was stored as literal text, not executed */
    sqlite3_stmt *sel;
    sqlite3_prepare_v2(db, "SELECT val FROM t;", -1, &sel, 0);
    sqlite3_step(sel);
    T_ASSERT_STR_EQ((const char*)sqlite3_column_text(sel, 0),
                    "'); DROP TABLE secret; --",
                    "injection stored as literal text");
    sqlite3_finalize(sel);

    /* Verify: secret table still exists */
    sqlite3_prepare_v2(db, "SELECT data FROM secret;", -1, &sel, 0);
    int rc = sqlite3_step(sel);
    T_ASSERT_INT_EQ(rc, SQLITE_ROW, "secret table still exists");
    T_ASSERT_STR_EQ((const char*)sqlite3_column_text(sel, 0),
                    "top_secret", "secret data intact");
    sqlite3_finalize(sel);

    csorma_str_free(injection);
    sqlite3_close(db);
    return true;
}

/* ============================================================
 *  TEST 10: Repeated bind/step/reset cycle — stress test
 *           for lifetime correctness under rapid reuse
 * ============================================================ */

static bool t_lifetime_rapid_rebind(void)
{
    sqlite3 *db = open_mem();
    sqlite3_exec(db, "CREATE TABLE t(idx INTEGER, val TEXT);", 0, 0, 0);

    sqlite3_stmt *stmt;
    sqlite3_prepare_v2(db, "INSERT INTO t VALUES(?1, ?2);", -1, &stmt, 0);

    for (int i = 0; i < 500; i++)
    {
        char buf[64];
        int len = snprintf(buf, sizeof(buf), "value_%d", i);
        csorma_s *s = csorma_str_build(buf, (uint32_t)len);

        bindvar_to_stmt(stmt, 1, BINDVAR_TYPE_Int, i, 0, NULL);
        bindvar_to_stmt(stmt, 2, BINDVAR_TYPE_String, 0, 0, s);
        sqlite3_step(stmt);
        sqlite3_reset(stmt);
        csorma_str_free(s);  /* free after reset — safe */
    }
    sqlite3_finalize(stmt);

    /* Verify count */
    sqlite3_stmt *sel;
    sqlite3_prepare_v2(db, "SELECT count(*) FROM t;", -1, &sel, 0);
    sqlite3_step(sel);
    T_ASSERT_INT_EQ(sqlite3_column_int(sel, 0), 500, "500 rows inserted");
    sqlite3_finalize(sel);

    /* Spot check first and last */
    sqlite3_prepare_v2(db, "SELECT val FROM t WHERE idx=0;", -1, &sel, 0);
    sqlite3_step(sel);
    T_ASSERT_STR_EQ((const char*)sqlite3_column_text(sel, 0), "value_0", "first");
    sqlite3_finalize(sel);

    sqlite3_prepare_v2(db, "SELECT val FROM t WHERE idx=499;", -1, &sel, 0);
    sqlite3_step(sel);
    T_ASSERT_STR_EQ((const char*)sqlite3_column_text(sel, 0), "value_499", "last");
    sqlite3_finalize(sel);

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
    printf("   CSORMA SQLITE_STATIC BINDING LIFETIME TESTS\n");
    printf("   Source: ../template/csorma.c (compiled directly)\n");
    printf("   NOTE: Run with 'make asan_all' for use-after-free detection\n");
    printf("  ================================================================\n");
    printf(C_RESET "\n");

    TEST_SUITE("Correct lifetime ordering");
    RUN_TEST(t_lifetime_correct_order);
    RUN_TEST(t_lifetime_finalize_then_free);
    RUN_TEST(t_lifetime_multiple_binds);
    SUITE_END();

    TEST_SUITE("Bindvar helper lifetime");
    RUN_TEST(t_lifetime_where_bindvars);
    RUN_TEST(t_lifetime_set_bindvars);
    SUITE_END();

    TEST_SUITE("Rebind and reuse");
    RUN_TEST(t_lifetime_rebind_after_reset);
    RUN_TEST(t_lifetime_rapid_rebind);
    SUITE_END();

    TEST_SUITE("String edge cases");
    RUN_TEST(t_lifetime_large_string);
    RUN_TEST(t_lifetime_empty_string);
    SUITE_END();

    TEST_SUITE("SQL injection via bound parameter");
    RUN_TEST(t_lifetime_injection_in_bound_string);
    SUITE_END();

    return test_summary("SQLITE_STATIC Binding Lifetime");
}
