/*
 * test_db_ops.c — Tests for OrmaDatabase_* functions
 * Links against REAL csorma.c + SQLite amalgamation
 */
#include "test_framework.h"
#include "csorma.h"

static bool t_db_init_memory(void) {
    OrmaDatabase *o = OrmaDatabase_init((const uint8_t*)":memory:", 8,
                                         (const uint8_t*)"", 0);
    T_ASSERT_PTR_NOT_NULL(o, "in-memory db");
    OrmaDatabase_shutdown(o);
    return true;
}

static bool t_db_init_file(void) {
    OrmaDatabase *o = OrmaDatabase_init((const uint8_t*)"./", 2,
                                         (const uint8_t*)"_unit_test_tmp.db", 17);
    T_ASSERT_PTR_NOT_NULL(o, "file db");
    OrmaDatabase_shutdown(o);
    remove("_unit_test_tmp.db");
    return true;
}

static bool t_db_create_table(void) {
    OrmaDatabase *o = OrmaDatabase_init((const uint8_t*)":memory:", 8,
                                         (const uint8_t*)"", 0);
    CSORMA_GENERIC_RESULT r = OrmaDatabase_run_multi_sql(o,
        (const uint8_t*)"CREATE TABLE t1(id INTEGER PRIMARY KEY, name TEXT);");
    T_ASSERT_INT_EQ(r, CSORMA_GENERIC_RESULT_OK, "create table");
    OrmaDatabase_shutdown(o);
    return true;
}

static bool t_db_multi_sql(void) {
    OrmaDatabase *o = OrmaDatabase_init((const uint8_t*)":memory:", 8,
                                         (const uint8_t*)"", 0);
    CSORMA_GENERIC_RESULT r = OrmaDatabase_run_multi_sql(o,
        (const uint8_t*)"CREATE TABLE t(x INT); INSERT INTO t VALUES(1); INSERT INTO t VALUES(2);");
    T_ASSERT_INT_EQ(r, CSORMA_GENERIC_RESULT_OK, "multi sql");
    int64_t count = OrmaDatabase_run_sql_int64(o, (const uint8_t*)"SELECT count(*) FROM t;");
    T_ASSERT_INT_EQ(count, 2, "row count");
    OrmaDatabase_shutdown(o);
    return true;
}

static bool t_db_run_sql_int64(void) {
    OrmaDatabase *o = OrmaDatabase_init((const uint8_t*)":memory:", 8,
                                         (const uint8_t*)"", 0);
    OrmaDatabase_run_multi_sql(o, (const uint8_t*)"CREATE TABLE t(x INT); INSERT INTO t VALUES(42);");
    int64_t val = OrmaDatabase_run_sql_int64(o, (const uint8_t*)"SELECT x FROM t;");
    T_ASSERT_INT_EQ(val, 42, "value=42");
    OrmaDatabase_shutdown(o);
    return true;
}

static bool t_db_shutdown_null(void) {
    OrmaDatabase_shutdown(NULL);
    return true;
}

static bool t_db_run_sql_null(void) {
    CSORMA_GENERIC_RESULT r = OrmaDatabase_run_multi_sql(NULL, (const uint8_t*)"SELECT 1;");
    T_ASSERT_INT_EQ(r, CSORMA_GENERIC_RESULT_ERROR, "NULL db returns error");
    return true;
}

static bool t_db_wal_mode(void) {
    OrmaDatabase *o = OrmaDatabase_init((const uint8_t*)":memory:", 8,
                                         (const uint8_t*)"", 0);
    CSORMA_GENERIC_RESULT r = OrmaDatabase_set_wal_mode(o, true);
    T_ASSERT_INT_EQ(r, CSORMA_GENERIC_RESULT_OK, "wal on");
    r = OrmaDatabase_set_wal_mode(o, false);
    T_ASSERT_INT_EQ(r, CSORMA_GENERIC_RESULT_OK, "wal off");
    OrmaDatabase_shutdown(o);
    return true;
}

static bool t_db_invalid_sql(void) {
    OrmaDatabase *o = OrmaDatabase_init((const uint8_t*)":memory:", 8,
                                         (const uint8_t*)"", 0);
    CSORMA_GENERIC_RESULT r = OrmaDatabase_run_multi_sql(o,
        (const uint8_t*)"THIS IS NOT VALID SQL;");
    T_ASSERT_INT_EQ(r, CSORMA_GENERIC_RESULT_ERROR, "invalid sql");
    OrmaDatabase_shutdown(o);
    return true;
}

static bool t_db_sql_injection_surface(void) {
    OrmaDatabase *o = OrmaDatabase_init((const uint8_t*)":memory:", 8,
                                         (const uint8_t*)"", 0);
    OrmaDatabase_run_multi_sql(o, (const uint8_t*)"CREATE TABLE t(id INT);");
    /* run_multi_sql uses sqlite3_exec — stacked queries WILL execute */
    OrmaDatabase_run_multi_sql(o,
        (const uint8_t*)"INSERT INTO t VALUES(1); DROP TABLE t; --");
    int64_t val = OrmaDatabase_run_sql_int64(o,
        (const uint8_t*)"SELECT count(*) FROM sqlite_master WHERE name='t';");
    T_ASSERT_INT_EQ(val, 0, "table dropped (injection surface confirmed)");
    OrmaDatabase_shutdown(o);
    return true;
}

static bool t_db_mutex(void) {
    OrmaDatabase_lock_lastrowid_mutex();
    OrmaDatabase_unlock_lastrowid_mutex();
    return true;
}

int main(void) {
    printf(C_BOLD "\n");
    printf("  ================================================================\n");
    printf("   CSORMA DATABASE OPERATION TESTS\n");
    printf("   Source: ../template/csorma.c + SQLite amalgamation\n");
    printf("  ================================================================\n");
    printf(C_RESET "\n");

    TEST_SUITE("OrmaDatabase_init / shutdown");
    RUN_TEST(t_db_init_memory);
    RUN_TEST(t_db_init_file);
    RUN_TEST(t_db_shutdown_null);
    SUITE_END();

    TEST_SUITE("OrmaDatabase_run_multi_sql");
    RUN_TEST(t_db_create_table);
    RUN_TEST(t_db_multi_sql);
    RUN_TEST(t_db_run_sql_null);
    RUN_TEST(t_db_invalid_sql);
    SUITE_END();

    TEST_SUITE("OrmaDatabase_run_sql_int64");
    RUN_TEST(t_db_run_sql_int64);
    SUITE_END();

    TEST_SUITE("WAL mode");
    RUN_TEST(t_db_wal_mode);
    SUITE_END();

    TEST_SUITE("Security: SQL injection surface");
    RUN_TEST(t_db_sql_injection_surface);
    SUITE_END();

    TEST_SUITE("Mutex");
    RUN_TEST(t_db_mutex);
    SUITE_END();

    return test_summary("Database Operations");
}
