/*
 * test_resultset.c — Tests for __rs_get* functions
 */
#include "test_framework.h"
#include "csorma.h"
#include "sqlite3.h"

static sqlite3 *_open_db(void) {
    sqlite3 *db;
    sqlite3_open(":memory:", &db);
    sqlite3_exec(db,
        "CREATE TABLE t(id INTEGER, name TEXT, flag BOOLEAN);"
        "INSERT INTO t VALUES(1,'hello',1);"
        "INSERT INTO t VALUES(2,'world',0);"
        "INSERT INTO t VALUES(3,NULL,NULL);", 0, 0, 0);
    return db;
}

static bool t_getlong(void) {
    sqlite3 *db = _open_db();
    sqlite3_stmt *st;
    sqlite3_prepare_v2(db, "SELECT id FROM t WHERE id=1;", -1, &st, 0);
    sqlite3_step(st);
    T_ASSERT_INT_EQ(__rs_getLong(st, "id"), 1, "id=1");
    sqlite3_finalize(st);
    sqlite3_close(db);
    return true;
}

static bool t_getstring(void) {
    sqlite3 *db = _open_db();
    sqlite3_stmt *st;
    sqlite3_prepare_v2(db, "SELECT name FROM t WHERE id=1;", -1, &st, 0);
    sqlite3_step(st);
    csorma_s *s = __rs_getString(st, "name");
    T_ASSERT_PTR_NOT_NULL(s, "non-null");
    T_ASSERT_INT_EQ(s->l, 5, "len=5");
    T_ASSERT_MEM_EQ(s->s, "hello", 5, "content");
    csorma_str_free(s);
    sqlite3_finalize(st);
    sqlite3_close(db);
    return true;
}

static bool t_getstring_null(void) {
    sqlite3 *db = _open_db();
    sqlite3_stmt *st;
    sqlite3_prepare_v2(db, "SELECT name FROM t WHERE id=3;", -1, &st, 0);
    sqlite3_step(st);
    csorma_s *s = __rs_getString(st, "name");
    T_ASSERT_PTR_NOT_NULL(s, "returns empty for NULL col");
    T_ASSERT_INT_EQ(s->l, 0, "empty string");
    csorma_str_free(s);
    sqlite3_finalize(st);
    sqlite3_close(db);
    return true;
}

static bool t_getint(void) {
    sqlite3 *db = _open_db();
    sqlite3_stmt *st;
    sqlite3_prepare_v2(db, "SELECT id FROM t WHERE id=2;", -1, &st, 0);
    sqlite3_step(st);
    T_ASSERT_INT_EQ(__rs_getInt(st, "id"), 2, "id=2");
    sqlite3_finalize(st);
    sqlite3_close(db);
    return true;
}

static bool t_getbool_true(void) {
    sqlite3 *db = _open_db();
    sqlite3_stmt *st;
    sqlite3_prepare_v2(db, "SELECT flag FROM t WHERE id=1;", -1, &st, 0);
    sqlite3_step(st);
    T_ASSERT(__rs_getBoolean(st, "flag") == true, "flag=true");
    sqlite3_finalize(st);
    sqlite3_close(db);
    return true;
}

static bool t_getbool_false(void) {
    sqlite3 *db = _open_db();
    sqlite3_stmt *st;
    sqlite3_prepare_v2(db, "SELECT flag FROM t WHERE id=2;", -1, &st, 0);
    sqlite3_step(st);
    T_ASSERT(__rs_getBoolean(st, "flag") == false, "flag=false");
    sqlite3_finalize(st);
    sqlite3_close(db);
    return true;
}

static bool t_missing_column(void) {
    sqlite3 *db = _open_db();
    sqlite3_stmt *st;
    sqlite3_prepare_v2(db, "SELECT id FROM t WHERE id=1;", -1, &st, 0);
    sqlite3_step(st);
    /* This calls sqlite3_column_int64(stmt, -1) — undefined behavior! */
    int64_t val = __rs_getLong(st, "nonexistent");
    printf("         (note: missing column returned %lld — UB in rs_find_column_idx)\n",
           (long long)val);
    sqlite3_finalize(st);
    sqlite3_close(db);
    return true;
}

int main(void) {
    printf(C_BOLD "\n  CSORMA RESULT SET TESTS\n" C_RESET "\n");

    TEST_SUITE("__rs_getLong");
    RUN_TEST(t_getlong);
    SUITE_END();

    TEST_SUITE("__rs_getString");
    RUN_TEST(t_getstring);
    RUN_TEST(t_getstring_null);
    SUITE_END();

    TEST_SUITE("__rs_getInt");
    RUN_TEST(t_getint);
    SUITE_END();

    TEST_SUITE("__rs_getBoolean");
    RUN_TEST(t_getbool_true);
    RUN_TEST(t_getbool_false);
    SUITE_END();

    TEST_SUITE("Edge: missing column (UB)");
    RUN_TEST(t_missing_column);
    SUITE_END();

    return test_summary("Result Set");
}
