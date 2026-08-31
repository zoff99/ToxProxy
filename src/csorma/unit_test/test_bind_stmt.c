/*
 * test_bind_stmt.c — Tests for bindvar_to_stmt, bind_all_set_bindvars,
 *                    and bind_all_where_bindvars
 *
 * These functions perform the actual sqlite3_bind_*() calls that make
 * parameterized queries work. They are the core SQL injection defense.
 *
 * Tests verify:
 *   - Correct sqlite3_bind_int/int64/text calls
 *   - Correct parameter index mapping (offset 400 for WHERE, 600 for SET)
 *   - NULL string binding
 *   - Mixed types in one statement
 *   - Empty and NULL bindvar lists
 *   - Round-trip: bind → execute → read back → verify values
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

/* Create a table and return a prepared INSERT statement with
 * parameters at specific indices */
static sqlite3_stmt *prepare_with_params(sqlite3 *db, const char *sql)
{
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, 0);
    if (rc != SQLITE_OK)
        return NULL;
    return stmt;
}

/* ============================================================
 *  bindvar_to_stmt — individual binding tests
 * ============================================================ */

static bool t_bind_stmt_int(void)
{
    sqlite3 *db = open_mem();
    sqlite3_exec(db, "CREATE TABLE t(a INTEGER);", 0, 0, 0);

    sqlite3_stmt *stmt = prepare_with_params(db, "INSERT INTO t VALUES(?1);");
    T_ASSERT_PTR_NOT_NULL(stmt, "prepare");

    bindvar_to_stmt(stmt, 1, BINDVAR_TYPE_Int, 42, 0, NULL);

    int rc = sqlite3_step(stmt);
    T_ASSERT_INT_EQ(rc, SQLITE_DONE, "insert ok");
    sqlite3_finalize(stmt);

    /* Read back */
    sqlite3_stmt *sel;
    sqlite3_prepare_v2(db, "SELECT a FROM t;", -1, &sel, 0);
    sqlite3_step(sel);
    T_ASSERT_INT_EQ(sqlite3_column_int(sel, 0), 42, "value=42");
    sqlite3_finalize(sel);
    sqlite3_close(db);
    return true;
}

static bool t_bind_stmt_long(void)
{
    sqlite3 *db = open_mem();
    sqlite3_exec(db, "CREATE TABLE t(a INTEGER);", 0, 0, 0);

    sqlite3_stmt *stmt = prepare_with_params(db, "INSERT INTO t VALUES(?1);");
    T_ASSERT_PTR_NOT_NULL(stmt, "prepare");

    int64_t big = 9223372036854775807LL; /* INT64_MAX */
    bindvar_to_stmt(stmt, 1, BINDVAR_TYPE_Long, 0, big, NULL);

    sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    sqlite3_stmt *sel;
    sqlite3_prepare_v2(db, "SELECT a FROM t;", -1, &sel, 0);
    sqlite3_step(sel);
    int64_t val = sqlite3_column_int64(sel, 0);
    T_ASSERT_INT_EQ(val, big, "INT64_MAX preserved");
    sqlite3_finalize(sel);
    sqlite3_close(db);
    return true;
}

static bool t_bind_stmt_boolean_true(void)
{
    sqlite3 *db = open_mem();
    sqlite3_exec(db, "CREATE TABLE t(a BOOLEAN);", 0, 0, 0);

    sqlite3_stmt *stmt = prepare_with_params(db, "INSERT INTO t VALUES(?1);");
    bindvar_to_stmt(stmt, 1, BINDVAR_TYPE_Boolean, 1, 0, NULL);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    sqlite3_stmt *sel;
    sqlite3_prepare_v2(db, "SELECT a FROM t;", -1, &sel, 0);
    sqlite3_step(sel);
    T_ASSERT_INT_EQ(sqlite3_column_int(sel, 0), 1, "true=1");
    sqlite3_finalize(sel);
    sqlite3_close(db);
    return true;
}

static bool t_bind_stmt_boolean_false(void)
{
    sqlite3 *db = open_mem();
    sqlite3_exec(db, "CREATE TABLE t(a BOOLEAN);", 0, 0, 0);

    sqlite3_stmt *stmt = prepare_with_params(db, "INSERT INTO t VALUES(?1);");
    bindvar_to_stmt(stmt, 1, BINDVAR_TYPE_Boolean, 0, 0, NULL);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    sqlite3_stmt *sel;
    sqlite3_prepare_v2(db, "SELECT a FROM t;", -1, &sel, 0);
    sqlite3_step(sel);
    T_ASSERT_INT_EQ(sqlite3_column_int(sel, 0), 0, "false=0");
    sqlite3_finalize(sel);
    sqlite3_close(db);
    return true;
}

static bool t_bind_stmt_string(void)
{
    sqlite3 *db = open_mem();
    sqlite3_exec(db, "CREATE TABLE t(a TEXT);", 0, 0, 0);

    sqlite3_stmt *stmt = prepare_with_params(db, "INSERT INTO t VALUES(?1);");
    csorma_s *str = csorma_str2_build("hello world");
    bindvar_to_stmt(stmt, 1, BINDVAR_TYPE_String, 0, 0, str);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    sqlite3_stmt *sel;
    sqlite3_prepare_v2(db, "SELECT a FROM t;", -1, &sel, 0);
    sqlite3_step(sel);
    const char *val = (const char *)sqlite3_column_text(sel, 0);
    T_ASSERT(val != NULL, "non-null");
    T_ASSERT_STR_EQ(val, "hello world", "content");
    sqlite3_finalize(sel);
    sqlite3_close(db);
    csorma_str_free(str);
    return true;
}

static bool t_bind_stmt_string_binary(void)
{
    sqlite3 *db = open_mem();
    sqlite3_exec(db, "CREATE TABLE t(a TEXT);", 0, 0, 0);

    sqlite3_stmt *stmt = prepare_with_params(db, "INSERT INTO t VALUES(?1);");
    const char bin[] = {'A', '\0', 'B', '\0', 'C'};
    csorma_s *str = csorma_str_build(bin, 5);
    bindvar_to_stmt(stmt, 1, BINDVAR_TYPE_String, 0, 0, str);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    sqlite3_stmt *sel;
    sqlite3_prepare_v2(db, "SELECT a FROM t;", -1, &sel, 0);
    sqlite3_step(sel);
    int len = sqlite3_column_bytes(sel, 0);
    const unsigned char *val = sqlite3_column_text(sel, 0);
    T_ASSERT_INT_EQ(len, 5, "binary length preserved");
    T_ASSERT_MEM_EQ(val, bin, 5, "binary content preserved");
    sqlite3_finalize(sel);
    sqlite3_close(db);
    csorma_str_free(str);
    return true;
}

static bool t_bind_stmt_null_string(void)
{
    sqlite3 *db = open_mem();
    sqlite3_exec(db, "CREATE TABLE t(a TEXT);", 0, 0, 0);

    sqlite3_stmt *stmt = prepare_with_params(db, "INSERT INTO t VALUES(?1);");
    bindvar_to_stmt(stmt, 1, BINDVAR_TYPE_String, 0, 0, NULL);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    sqlite3_stmt *sel;
    sqlite3_prepare_v2(db, "SELECT a FROM t;", -1, &sel, 0);
    sqlite3_step(sel);
    int type = sqlite3_column_type(sel, 0);
    T_ASSERT_INT_EQ(type, SQLITE_NULL, "NULL stored in DB");
    sqlite3_finalize(sel);
    sqlite3_close(db);
    return true;
}

static bool t_bind_stmt_negative_int(void)
{
    sqlite3 *db = open_mem();
    sqlite3_exec(db, "CREATE TABLE t(a INTEGER);", 0, 0, 0);

    sqlite3_stmt *stmt = prepare_with_params(db, "INSERT INTO t VALUES(?1);");
    bindvar_to_stmt(stmt, 1, BINDVAR_TYPE_Int, -999, 0, NULL);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    sqlite3_stmt *sel;
    sqlite3_prepare_v2(db, "SELECT a FROM t;", -1, &sel, 0);
    sqlite3_step(sel);
    T_ASSERT_INT_EQ(sqlite3_column_int(sel, 0), -999, "negative preserved");
    sqlite3_finalize(sel);
    sqlite3_close(db);
    return true;
}

/* ============================================================
 *  bind_all_where_bindvars — offset 400
 * ============================================================ */

static bool t_bind_all_where_single(void)
{
    sqlite3 *db = open_mem();
    sqlite3_exec(db,
        "CREATE TABLE t(id INTEGER, name TEXT);"
        "INSERT INTO t VALUES(1, 'alice');"
        "INSERT INTO t VALUES(2, 'bob');",
        0, 0, 0);

    /* Build WHERE bindvars */
    OrmaBindvars *bv = bindvar_init(NULL);
    bv = bindvar_add_n(bv, 2, BINDVAR_TYPE_Int);

    /* Prepare statement with ?400 */
    sqlite3_stmt *stmt = prepare_with_params(db,
        "SELECT name FROM t WHERE id = ?400;");
    T_ASSERT_PTR_NOT_NULL(stmt, "prepare with ?400");

    bind_all_where_bindvars(stmt, bv);

    int rc = sqlite3_step(stmt);
    T_ASSERT_INT_EQ(rc, SQLITE_ROW, "got row");
    const char *name = (const char *)sqlite3_column_text(stmt, 0);
    T_ASSERT_STR_EQ(name, "bob", "WHERE id=2 returns bob");

    sqlite3_finalize(stmt);
    bindvar_free(bv);
    sqlite3_close(db);
    return true;
}

static bool t_bind_all_where_multiple(void)
{
    sqlite3 *db = open_mem();
    sqlite3_exec(db,
        "CREATE TABLE t(a INTEGER, b INTEGER, c TEXT);"
        "INSERT INTO t VALUES(1, 10, 'x');"
        "INSERT INTO t VALUES(2, 20, 'y');"
        "INSERT INTO t VALUES(3, 30, 'z');",
        0, 0, 0);

    OrmaBindvars *bv = bindvar_init(NULL);
    bv = bindvar_add_n(bv, 2, BINDVAR_TYPE_Int);    /* ?400 */
    bv = bindvar_add_n(bv, 20, BINDVAR_TYPE_Int);   /* ?401 */

    sqlite3_stmt *stmt = prepare_with_params(db,
        "SELECT c FROM t WHERE a = ?400 AND b = ?401;");
    T_ASSERT_PTR_NOT_NULL(stmt, "prepare");

    bind_all_where_bindvars(stmt, bv);

    int rc = sqlite3_step(stmt);
    T_ASSERT_INT_EQ(rc, SQLITE_ROW, "got row");
    const char *val = (const char *)sqlite3_column_text(stmt, 0);
    T_ASSERT_STR_EQ(val, "y", "a=2 AND b=20 returns 'y'");

    sqlite3_finalize(stmt);
    bindvar_free(bv);
    sqlite3_close(db);
    return true;
}

static bool t_bind_all_where_string(void)
{
    sqlite3 *db = open_mem();
    sqlite3_exec(db,
        "CREATE TABLE t(name TEXT, score INTEGER);"
        "INSERT INTO t VALUES('alice', 100);"
        "INSERT INTO t VALUES('bob', 200);",
        0, 0, 0);

    OrmaBindvars *bv = bindvar_init(NULL);
    csorma_s *str = csorma_str2_build("bob");
    bv = bindvar_add_s(bv, str);   /* ?400 */

    sqlite3_stmt *stmt = prepare_with_params(db,
        "SELECT score FROM t WHERE name = ?400;");
    bind_all_where_bindvars(stmt, bv);

    int rc = sqlite3_step(stmt);
    T_ASSERT_INT_EQ(rc, SQLITE_ROW, "got row");
    T_ASSERT_INT_EQ(sqlite3_column_int(stmt, 0), 200, "bob's score=200");

    sqlite3_finalize(stmt);
    bindvar_free(bv);
    sqlite3_close(db);
    return true;
}

static bool t_bind_all_where_mixed_types(void)
{
    sqlite3 *db = open_mem();
    sqlite3_exec(db,
        "CREATE TABLE t(a INTEGER, b TEXT, c INTEGER);"
        "INSERT INTO t VALUES(1, 'hello', 1);"
        "INSERT INTO t VALUES(2, 'world', 0);"
        "INSERT INTO t VALUES(3, 'hello', 0);",
        0, 0, 0);

    OrmaBindvars *bv = bindvar_init(NULL);
    bv = bindvar_add_n(bv, 1, BINDVAR_TYPE_Int);             /* ?400 */
    csorma_s *str = csorma_str2_build("hello");
    bv = bindvar_add_s(bv, str);                              /* ?401 */
    bv = bindvar_add_n(bv, 1, BINDVAR_TYPE_Boolean);          /* ?402 */

    sqlite3_stmt *stmt = prepare_with_params(db,
        "SELECT count(*) FROM t WHERE a >= ?400 AND b = ?401 AND c = ?402;");
    bind_all_where_bindvars(stmt, bv);

    sqlite3_step(stmt);
    T_ASSERT_INT_EQ(sqlite3_column_int(stmt, 0), 1, "one match");

    sqlite3_finalize(stmt);
    bindvar_free(bv);
    sqlite3_close(db);
    return true;
}

static bool t_bind_all_where_empty(void)
{
    sqlite3 *db = open_mem();
    OrmaBindvars *bv = bindvar_init(NULL);

    /* Empty bindvars — should be a no-op, no crash */
    bind_all_where_bindvars(NULL, bv);
    bind_all_where_bindvars(NULL, NULL);

    bindvar_free(bv);
    sqlite3_close(db);
    return true;
}

/* ============================================================
 *  bind_all_set_bindvars — offset 600
 * ============================================================ */

static bool t_bind_all_set_single(void)
{
    sqlite3 *db = open_mem();
    sqlite3_exec(db,
        "CREATE TABLE t(id INTEGER, name TEXT);"
        "INSERT INTO t VALUES(1, 'old');",
        0, 0, 0);

    OrmaBindvars *bv = bindvar_init(NULL);
    csorma_s *str = csorma_str2_build("new_name");
    bv = bindvar_add_s(bv, str);   /* ?600 */

    sqlite3_stmt *stmt = prepare_with_params(db,
        "UPDATE t SET name = ?600 WHERE id = 1;");
    T_ASSERT_PTR_NOT_NULL(stmt, "prepare");

    bind_all_set_bindvars(stmt, bv);

    int rc = sqlite3_step(stmt);
    T_ASSERT_INT_EQ(rc, SQLITE_DONE, "update ok");
    sqlite3_finalize(stmt);

    /* Verify */
    sqlite3_stmt *sel;
    sqlite3_prepare_v2(db, "SELECT name FROM t WHERE id=1;", -1, &sel, 0);
    sqlite3_step(sel);
    const char *val = (const char *)sqlite3_column_text(sel, 0);
    T_ASSERT_STR_EQ(val, "new_name", "name updated");
    sqlite3_finalize(sel);

    bindvar_free(bv);
    sqlite3_close(db);
    return true;
}

static bool t_bind_all_set_multiple(void)
{
    sqlite3 *db = open_mem();
    sqlite3_exec(db,
        "CREATE TABLE t(a INTEGER, b TEXT, c INTEGER);"
        "INSERT INTO t VALUES(0, 'old', 0);",
        0, 0, 0);

    OrmaBindvars *bv = bindvar_init(NULL);
    bv = bindvar_add_n(bv, 42, BINDVAR_TYPE_Int);           /* ?600 */
    csorma_s *str = csorma_str2_build("updated");
    bv = bindvar_add_s(bv, str);                             /* ?601 */
    bv = bindvar_add_n(bv, 1, BINDVAR_TYPE_Boolean);         /* ?602 */

    sqlite3_stmt *stmt = prepare_with_params(db,
        "UPDATE t SET a = ?600, b = ?601, c = ?602;");
    bind_all_set_bindvars(stmt, bv);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    /* Verify all three columns */
    sqlite3_stmt *sel;
    sqlite3_prepare_v2(db, "SELECT a, b, c FROM t;", -1, &sel, 0);
    sqlite3_step(sel);
    T_ASSERT_INT_EQ(sqlite3_column_int(sel, 0), 42, "a=42");
    T_ASSERT_STR_EQ((const char*)sqlite3_column_text(sel, 1), "updated", "b='updated'");
    T_ASSERT_INT_EQ(sqlite3_column_int(sel, 2), 1, "c=1");
    sqlite3_finalize(sel);

    bindvar_free(bv);
    sqlite3_close(db);
    return true;
}

static bool t_bind_all_set_null_string(void)
{
    sqlite3 *db = open_mem();
    sqlite3_exec(db,
        "CREATE TABLE t(name TEXT);"
        "INSERT INTO t VALUES('something');",
        0, 0, 0);

    OrmaBindvars *bv = bindvar_init(NULL);
    bv = bindvar_add_s(bv, NULL);   /* ?600 = NULL */

    sqlite3_stmt *stmt = prepare_with_params(db,
        "UPDATE t SET name = ?600;");
    bind_all_set_bindvars(stmt, bv);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    sqlite3_stmt *sel;
    sqlite3_prepare_v2(db, "SELECT name FROM t;", -1, &sel, 0);
    sqlite3_step(sel);
    T_ASSERT_INT_EQ(sqlite3_column_type(sel, 0), SQLITE_NULL, "name is NULL");
    sqlite3_finalize(sel);

    bindvar_free(bv);
    sqlite3_close(db);
    return true;
}

static bool t_bind_all_set_empty(void)
{
    OrmaBindvars *bv = bindvar_init(NULL);
    bind_all_set_bindvars(NULL, bv);
    bind_all_set_bindvars(NULL, NULL);
    bindvar_free(bv);
    return true;
}

/* ============================================================
 *  Round-trip: bind → INSERT → SELECT → verify
 * ============================================================ */

static bool t_bind_roundtrip(void)
{
    sqlite3 *db = open_mem();
    sqlite3_exec(db,
        "CREATE TABLE t(id INTEGER, name TEXT, score INTEGER, active BOOLEAN);",
        0, 0, 0);

    /* Build bindvars for INSERT */
    OrmaBindvars *bv = bindvar_init(NULL);
    bv = bindvar_add_n(bv, 7, BINDVAR_TYPE_Int);
    csorma_s *name = csorma_str2_build("round_trip_test");
    bv = bindvar_add_s(bv, name);
    bv = bindvar_add_n(bv, 9999, BINDVAR_TYPE_Long);
    bv = bindvar_add_n(bv, 1, BINDVAR_TYPE_Boolean);

    sqlite3_stmt *stmt = prepare_with_params(db,
        "INSERT INTO t VALUES(?1, ?2, ?3, ?4);");

    /* Bind each manually using bindvar_to_stmt */
    bindvar_to_stmt(stmt, 1, bv->b[0].t, (int32_t)bv->b[0].n, bv->b[0].n, bv->b[0].s);
    bindvar_to_stmt(stmt, 2, bv->b[1].t, (int32_t)bv->b[1].n, bv->b[1].n, bv->b[1].s);
    bindvar_to_stmt(stmt, 3, bv->b[2].t, (int32_t)bv->b[2].n, bv->b[2].n, bv->b[2].s);
    bindvar_to_stmt(stmt, 4, bv->b[3].t, (int32_t)bv->b[3].n, bv->b[3].n, bv->b[3].s);

    sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    /* Read back and verify */
    sqlite3_stmt *sel;
    sqlite3_prepare_v2(db, "SELECT * FROM t;", -1, &sel, 0);
    sqlite3_step(sel);

    T_ASSERT_INT_EQ(sqlite3_column_int(sel, 0), 7, "id=7");
    T_ASSERT_STR_EQ((const char*)sqlite3_column_text(sel, 1), "round_trip_test", "name");
    T_ASSERT_INT_EQ(sqlite3_column_int64(sel, 2), 9999, "score=9999");
    T_ASSERT_INT_EQ(sqlite3_column_int(sel, 3), 1, "active=1");

    sqlite3_finalize(sel);
    bindvar_free(bv);
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
    printf("   CSORMA BIND-TO-STMT TESTS\n");
    printf("   Source: ../template/csorma.c (compiled directly)\n");
    printf("  ================================================================\n");
    printf(C_RESET "\n");

    TEST_SUITE("bindvar_to_stmt — individual");
    RUN_TEST(t_bind_stmt_int);
    RUN_TEST(t_bind_stmt_long);
    RUN_TEST(t_bind_stmt_boolean_true);
    RUN_TEST(t_bind_stmt_boolean_false);
    RUN_TEST(t_bind_stmt_string);
    RUN_TEST(t_bind_stmt_string_binary);
    RUN_TEST(t_bind_stmt_null_string);
    RUN_TEST(t_bind_stmt_negative_int);
    SUITE_END();

    TEST_SUITE("bind_all_where_bindvars (offset 400)");
    RUN_TEST(t_bind_all_where_single);
    RUN_TEST(t_bind_all_where_multiple);
    RUN_TEST(t_bind_all_where_string);
    RUN_TEST(t_bind_all_where_mixed_types);
    RUN_TEST(t_bind_all_where_empty);
    SUITE_END();

    TEST_SUITE("bind_all_set_bindvars (offset 600)");
    RUN_TEST(t_bind_all_set_single);
    RUN_TEST(t_bind_all_set_multiple);
    RUN_TEST(t_bind_all_set_null_string);
    RUN_TEST(t_bind_all_set_empty);
    SUITE_END();

    TEST_SUITE("Round-trip verification");
    RUN_TEST(t_bind_roundtrip);
    SUITE_END();

    return test_summary("Bind-to-Stmt");
}

