/*
 * test_error_recovery.c — Tests for error handling and recovery
 *
 * Verifies that the database remains usable after various error
 * conditions: invalid SQL, missing tables, constraint violations,
 * and sequences of errors.
 *
 * A database that cannot recover from errors is worse than one
 * that crashes — it silently produces wrong results.
 */

#include "test_framework.h"
#include "csorma.h"
#include "sqlite3.h"

/* ============================================================
 *  Helpers
 * ============================================================ */

static OrmaDatabase *open_mem_db(void)
{
    return OrmaDatabase_init((const uint8_t *)":memory:", 8,
                             (const uint8_t *)"", 0);
}

/* ============================================================
 *  TEST 1: INSERT into nonexistent table
 * ============================================================ */

static bool t_err_insert_nonexistent_table(void)
{
    OrmaDatabase *o = open_mem_db();
    T_ASSERT_PTR_NOT_NULL(o, "open");

    CSORMA_GENERIC_RESULT r = OrmaDatabase_run_multi_sql(o,
        (const uint8_t *)"INSERT INTO no_such_table VALUES(1);");
    T_ASSERT_INT_EQ(r, CSORMA_GENERIC_RESULT_ERROR, "returns error");

    /* DB must still be usable */
    r = OrmaDatabase_run_multi_sql(o,
        (const uint8_t *)"CREATE TABLE t(x INT);");
    T_ASSERT_INT_EQ(r, CSORMA_GENERIC_RESULT_OK, "DB still usable after error");

    OrmaDatabase_shutdown(o);
    return true;
}

/* ============================================================
 *  TEST 2: SELECT from nonexistent table
 * ============================================================ */

static bool t_err_select_nonexistent_table(void)
{
    OrmaDatabase *o = open_mem_db();

    int64_t val = OrmaDatabase_run_sql_int64(o,
        (const uint8_t *)"SELECT count(*) FROM no_such_table;");
    /* Should return 0 or negative (error), not crash */
    printf("         select from missing table returned: %lld\n", (long long)val);

    /* DB must still be usable */
    CSORMA_GENERIC_RESULT r = OrmaDatabase_run_multi_sql(o,
        (const uint8_t *)"CREATE TABLE t(x INT); INSERT INTO t VALUES(42);");
    T_ASSERT_INT_EQ(r, CSORMA_GENERIC_RESULT_OK, "DB still usable");

    int64_t v = OrmaDatabase_run_sql_int64(o,
        (const uint8_t *)"SELECT x FROM t;");
    T_ASSERT_INT_EQ(v, 42, "correct read after recovery");

    OrmaDatabase_shutdown(o);
    return true;
}

/* ============================================================
 *  TEST 3: Completely invalid SQL
 * ============================================================ */

static bool t_err_invalid_sql(void)
{
    OrmaDatabase *o = open_mem_db();

    CSORMA_GENERIC_RESULT r = OrmaDatabase_run_multi_sql(o,
        (const uint8_t *)"THIS IS NOT SQL AT ALL;");
    T_ASSERT_INT_EQ(r, CSORMA_GENERIC_RESULT_ERROR, "error for garbage");

    r = OrmaDatabase_run_multi_sql(o,
        (const uint8_t *)"SELECT FROM WHERE;");
    T_ASSERT_INT_EQ(r, CSORMA_GENERIC_RESULT_ERROR, "error for broken SQL");

    r = OrmaDatabase_run_multi_sql(o,
        (const uint8_t *)"DROP TABLE;");
    T_ASSERT_INT_EQ(r, CSORMA_GENERIC_RESULT_ERROR, "error for incomplete SQL");

    /* DB must still work */
    r = OrmaDatabase_run_multi_sql(o,
        (const uint8_t *)"CREATE TABLE t(x INT);");
    T_ASSERT_INT_EQ(r, CSORMA_GENERIC_RESULT_OK, "DB usable after invalid SQL");

    OrmaDatabase_shutdown(o);
    return true;
}

/* ============================================================
 *  TEST 4: UNIQUE constraint violation
 * ============================================================ */

static bool t_err_unique_constraint(void)
{
    OrmaDatabase *o = open_mem_db();

    OrmaDatabase_run_multi_sql(o,
        (const uint8_t *)"CREATE TABLE t(id INTEGER UNIQUE, val TEXT);");
    OrmaDatabase_run_multi_sql(o,
        (const uint8_t *)"INSERT INTO t VALUES(1, 'first');");

    /* Duplicate key — should fail */
    CSORMA_GENERIC_RESULT r = OrmaDatabase_run_multi_sql(o,
        (const uint8_t *)"INSERT INTO t VALUES(1, 'duplicate');");
    T_ASSERT_INT_EQ(r, CSORMA_GENERIC_RESULT_ERROR, "UNIQUE violation detected");

    /* Original data must be intact */
    int64_t count = OrmaDatabase_run_sql_int64(o,
        (const uint8_t *)"SELECT count(*) FROM t;");
    T_ASSERT_INT_EQ(count, 1, "still one row");

    /* DB must still be usable */
    r = OrmaDatabase_run_multi_sql(o,
        (const uint8_t *)"INSERT INTO t VALUES(2, 'second');");
    T_ASSERT_INT_EQ(r, CSORMA_GENERIC_RESULT_OK, "insert after constraint error");

    count = OrmaDatabase_run_sql_int64(o,
        (const uint8_t *)"SELECT count(*) FROM t;");
    T_ASSERT_INT_EQ(count, 2, "two rows now");

    OrmaDatabase_shutdown(o);
    return true;
}

/* ============================================================
 *  TEST 5: PRIMARY KEY constraint violation
 * ============================================================ */

static bool t_err_primary_key_constraint(void)
{
    OrmaDatabase *o = open_mem_db();

    OrmaDatabase_run_multi_sql(o,
        (const uint8_t *)"CREATE TABLE t(id INTEGER PRIMARY KEY, val TEXT);");
    OrmaDatabase_run_multi_sql(o,
        (const uint8_t *)"INSERT INTO t VALUES(1, 'first');");

    CSORMA_GENERIC_RESULT r = OrmaDatabase_run_multi_sql(o,
        (const uint8_t *)"INSERT INTO t VALUES(1, 'conflict');");
    T_ASSERT_INT_EQ(r, CSORMA_GENERIC_RESULT_ERROR, "PK violation detected");

    /* Verify data integrity */
    int64_t val = OrmaDatabase_run_sql_int64(o,
        (const uint8_t *)"SELECT count(*) FROM t WHERE val='first';");
    T_ASSERT_INT_EQ(val, 1, "original row intact");

    OrmaDatabase_shutdown(o);
    return true;
}

/* ============================================================
 *  TEST 6: NOT NULL constraint violation
 * ============================================================ */

static bool t_err_not_null_constraint(void)
{
    OrmaDatabase *o = open_mem_db();

    OrmaDatabase_run_multi_sql(o,
        (const uint8_t *)"CREATE TABLE t(id INTEGER, name TEXT NOT NULL);");

    CSORMA_GENERIC_RESULT r = OrmaDatabase_run_multi_sql(o,
        (const uint8_t *)"INSERT INTO t VALUES(1, NULL);");
    T_ASSERT_INT_EQ(r, CSORMA_GENERIC_RESULT_ERROR, "NOT NULL violation");

    /* DB still usable */
    r = OrmaDatabase_run_multi_sql(o,
        (const uint8_t *)"INSERT INTO t VALUES(1, 'valid');");
    T_ASSERT_INT_EQ(r, CSORMA_GENERIC_RESULT_OK, "valid insert after error");

    OrmaDatabase_shutdown(o);
    return true;
}

/* ============================================================
 *  TEST 7: Multiple errors in sequence
 * ============================================================ */

static bool t_err_multiple_sequential(void)
{
    OrmaDatabase *o = open_mem_db();

    /* Error 1: bad SQL */
    OrmaDatabase_run_multi_sql(o, (const uint8_t *)"GARBAGE;");

    /* Error 2: missing table */
    OrmaDatabase_run_multi_sql(o, (const uint8_t *)"SELECT * FROM missing;");

    /* Error 3: bad syntax */
    OrmaDatabase_run_multi_sql(o, (const uint8_t *)"CREATE TABLE;");

    /* Error 4: type mismatch in strict context */
    OrmaDatabase_run_multi_sql(o, (const uint8_t *)"INSERT INTO missing VALUES(1);");

    /* Error 5: another bad statement */
    OrmaDatabase_run_multi_sql(o, (const uint8_t *)"DROP DATABASE;");

    /* After 5 consecutive errors, DB must still work */
    CSORMA_GENERIC_RESULT r = OrmaDatabase_run_multi_sql(o,
        (const uint8_t *)"CREATE TABLE t(x INT); INSERT INTO t VALUES(99);");
    T_ASSERT_INT_EQ(r, CSORMA_GENERIC_RESULT_OK, "DB works after 5 errors");

    int64_t v = OrmaDatabase_run_sql_int64(o,
        (const uint8_t *)"SELECT x FROM t;");
    T_ASSERT_INT_EQ(v, 99, "correct value");

    OrmaDatabase_shutdown(o);
    return true;
}

/* ============================================================
 *  TEST 8: Error in middle of multi-statement SQL
 * ============================================================ */

static bool t_err_mid_multi_statement(void)
{
    OrmaDatabase *o = open_mem_db();

    OrmaDatabase_run_multi_sql(o,
        (const uint8_t *)"CREATE TABLE t(x INT);");

    /* First statement OK, second fails, third may or may not run */
    CSORMA_GENERIC_RESULT r = OrmaDatabase_run_multi_sql(o,
        (const uint8_t *)"INSERT INTO t VALUES(1); "
                         "INSERT INTO no_such_table VALUES(2); "
                         "INSERT INTO t VALUES(3);");

    /* sqlite3_exec stops at first error, so only first INSERT runs */
    printf("         multi-stmt with error in middle: result=%d\n", r);

    int64_t count = OrmaDatabase_run_sql_int64(o,
        (const uint8_t *)"SELECT count(*) FROM t;");
    printf("         rows in t: %lld\n", (long long)count);

    /* At least the first INSERT should have succeeded */
    T_ASSERT(count >= 1, "at least first insert succeeded");

    /* DB must still be usable */
    r = OrmaDatabase_run_multi_sql(o,
        (const uint8_t *)"INSERT INTO t VALUES(100);");
    T_ASSERT_INT_EQ(r, CSORMA_GENERIC_RESULT_OK, "DB usable after partial failure");

    OrmaDatabase_shutdown(o);
    return true;
}

/* ============================================================
 *  TEST 9: run_sql_int64 on empty result
 * ============================================================ */

static bool t_err_int64_empty_result(void)
{
    OrmaDatabase *o = open_mem_db();

    OrmaDatabase_run_multi_sql(o,
        (const uint8_t *)"CREATE TABLE t(x INT);");

    /* Query that returns no rows */
    int64_t val = OrmaDatabase_run_sql_int64(o,
        (const uint8_t *)"SELECT x FROM t WHERE x = 999;");
    printf("         empty result returned: %lld\n", (long long)val);

    /* Should return 0 (default), not crash */
    T_ASSERT_INT_EQ(val, 0, "empty result returns 0");

    OrmaDatabase_shutdown(o);
    return true;
}

/* ============================================================
 *  TEST 10: run_sql_int64 on multi-row result
 * ============================================================ */

static bool t_err_int64_multi_row(void)
{
    OrmaDatabase *o = open_mem_db();

    OrmaDatabase_run_multi_sql(o,
        (const uint8_t *)"CREATE TABLE t(x INT);"
                         "INSERT INTO t VALUES(10);"
                         "INSERT INTO t VALUES(20);"
                         "INSERT INTO t VALUES(30);");

    /* Query returns multiple rows — function should return last value */
    int64_t val = OrmaDatabase_run_sql_int64(o,
        (const uint8_t *)"SELECT x FROM t;");
    printf("         multi-row returned: %lld\n", (long long)val);

    /* The function iterates all rows and keeps the last value */
    T_ASSERT_INT_EQ(val, 30, "returns last row's value");

    OrmaDatabase_shutdown(o);
    return true;
}

/* ============================================================
 *  TEST 11: DROP table then query it
 * ============================================================ */

static bool t_err_drop_then_query(void)
{
    OrmaDatabase *o = open_mem_db();

    OrmaDatabase_run_multi_sql(o,
        (const uint8_t *)"CREATE TABLE t(x INT); INSERT INTO t VALUES(1);");

    /* Drop the table */
    OrmaDatabase_run_multi_sql(o,
        (const uint8_t *)"DROP TABLE t;");

    /* Query the dropped table — should error, not crash */
    int64_t val = OrmaDatabase_run_sql_int64(o,
        (const uint8_t *)"SELECT x FROM t;");
    printf("         query dropped table returned: %lld\n", (long long)val);

    /* Recreate and verify DB works */
    CSORMA_GENERIC_RESULT r = OrmaDatabase_run_multi_sql(o,
        (const uint8_t *)"CREATE TABLE t(x INT); INSERT INTO t VALUES(42);");
    T_ASSERT_INT_EQ(r, CSORMA_GENERIC_RESULT_OK, "recreate after drop");

    int64_t v = OrmaDatabase_run_sql_int64(o,
        (const uint8_t *)"SELECT x FROM t;");
    T_ASSERT_INT_EQ(v, 42, "correct after recreate");

    OrmaDatabase_shutdown(o);
    return true;
}

/* ============================================================
 *  TEST 12: Very long SQL statement
 * ============================================================ */

static bool t_err_very_long_sql(void)
{
    OrmaDatabase *o = open_mem_db();

    OrmaDatabase_run_multi_sql(o,
        (const uint8_t *)"CREATE TABLE t(x INT);");

    /* Build a very long INSERT statement */
    char *sql = calloc(1, 100000);
    strcpy(sql, "INSERT INTO t VALUES(1);");
    for (int i = 2; i < 1000; i++)
    {
        char tmp[64];
        snprintf(tmp, sizeof(tmp), "INSERT INTO t VALUES(%d);", i);
        strcat(sql, tmp);
    }

    CSORMA_GENERIC_RESULT r = OrmaDatabase_run_multi_sql(o, (const uint8_t *)sql);
    T_ASSERT_INT_EQ(r, CSORMA_GENERIC_RESULT_OK, "long multi-sql ok");

    int64_t count = OrmaDatabase_run_sql_int64(o,
        (const uint8_t *)"SELECT count(*) FROM t;");
    T_ASSERT_INT_EQ(count, 999, "999 rows inserted");

    free(sql);
    OrmaDatabase_shutdown(o);
    return true;
}

/* ============================================================
 *  TEST 13: Empty SQL string
 * ============================================================ */

static bool t_err_empty_sql(void)
{
    OrmaDatabase *o = open_mem_db();

    CSORMA_GENERIC_RESULT r = OrmaDatabase_run_multi_sql(o,
        (const uint8_t *)"");
    /* Empty string — sqlite3_exec should handle gracefully */
    printf("         empty SQL result: %d\n", r);

    /* DB must still work */
    r = OrmaDatabase_run_multi_sql(o,
        (const uint8_t *)"CREATE TABLE t(x INT);");
    T_ASSERT_INT_EQ(r, CSORMA_GENERIC_RESULT_OK, "DB usable after empty SQL");

    OrmaDatabase_shutdown(o);
    return true;
}

/* ============================================================
 *  TEST 14: SQL with only whitespace/comments
 * ============================================================ */

static bool t_err_whitespace_sql(void)
{
    OrmaDatabase *o = open_mem_db();

    CSORMA_GENERIC_RESULT r = OrmaDatabase_run_multi_sql(o,
        (const uint8_t *)"   \n\t  ");
    printf("         whitespace SQL result: %d\n", r);

    r = OrmaDatabase_run_multi_sql(o,
        (const uint8_t *)"-- just a comment\n");
    printf("         comment SQL result: %d\n", r);

    /* DB must still work */
    r = OrmaDatabase_run_multi_sql(o,
        (const uint8_t *)"CREATE TABLE t(x INT);");
    T_ASSERT_INT_EQ(r, CSORMA_GENERIC_RESULT_OK, "DB usable");

    OrmaDatabase_shutdown(o);
    return true;
}

/* ============================================================
 *  MAIN
 * ============================================================ */
int main(void)
{
    printf(C_BOLD "\n");
    printf("  ================================================================\n");
    printf("   CSORMA ERROR RECOVERY TESTS\n");
    printf("   Source: ../template/csorma.c (compiled directly)\n");
    printf("  ================================================================\n");
    printf(C_RESET "\n");

    TEST_SUITE("Nonexistent table errors");
    RUN_TEST(t_err_insert_nonexistent_table);
    RUN_TEST(t_err_select_nonexistent_table);
    SUITE_END();

    TEST_SUITE("Invalid SQL");
    RUN_TEST(t_err_invalid_sql);
    RUN_TEST(t_err_empty_sql);
    RUN_TEST(t_err_whitespace_sql);
    SUITE_END();

    TEST_SUITE("Constraint violations");
    RUN_TEST(t_err_unique_constraint);
    RUN_TEST(t_err_primary_key_constraint);
    RUN_TEST(t_err_not_null_constraint);
    SUITE_END();

    TEST_SUITE("Sequential and compound errors");
    RUN_TEST(t_err_multiple_sequential);
    RUN_TEST(t_err_mid_multi_statement);
    SUITE_END();

    TEST_SUITE("Edge case queries");
    RUN_TEST(t_err_int64_empty_result);
    RUN_TEST(t_err_int64_multi_row);
    RUN_TEST(t_err_drop_then_query);
    RUN_TEST(t_err_very_long_sql);
    SUITE_END();

    return test_summary("Error Recovery");
}

