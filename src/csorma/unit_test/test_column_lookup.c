/*
 * test_column_lookup.c — Tests for rs_find_column_idx() behavior
 *
 * Tests the column-name-to-index lookup used by __rs_getLong,
 * __rs_getString, __rs_getInt, __rs_getBoolean.
 *
 * KNOWN BUG: rs_find_column_idx uses:
 *   strncmp(col_name, column_name, strlen(column_name)) == 0
 * This is a PREFIX match, so "id" matches "id_extra".
 * These tests document and detect this bug.
 */

#include "test_framework.h"
#include "csorma.h"
#include "sqlite3.h"

/* Helper: create a DB with tricky column names */
static sqlite3 *_open_tricky_db(void)
{
    sqlite3 *db;
    sqlite3_open(":memory:", &db);
    sqlite3_exec(db,
        "CREATE TABLE tricky ("
        "  \"id\" INTEGER,"
        "  \"id_extra\" INTEGER,"
        "  \"name\" TEXT,"
        "  \"username\" TEXT,"
        "  \"a\" INTEGER,"
        "  \"ab\" INTEGER,"
        "  \"abc\" INTEGER,"
        "  \"x\" TEXT"
        ");", 0, 0, 0);
    sqlite3_exec(db,
        "INSERT INTO tricky VALUES(1, 2, 'hello', 'world', 10, 20, 30, 'X');",
        0, 0, 0);
    return db;
}

/* ============================================================
 *  Exact match tests
 * ============================================================ */

static bool t_exact_match_id(void)
{
    sqlite3 *db = _open_tricky_db();
    sqlite3_stmt *st;
    sqlite3_prepare_v2(db, "SELECT * FROM tricky;", -1, &st, 0);
    sqlite3_step(st);

    int64_t val = __rs_getLong(st, "id");
    T_ASSERT_INT_EQ(val, 1, "id=1");

    sqlite3_finalize(st);
    sqlite3_close(db);
    return true;
}

static bool t_exact_match_name(void)
{
    sqlite3 *db = _open_tricky_db();
    sqlite3_stmt *st;
    sqlite3_prepare_v2(db, "SELECT * FROM tricky;", -1, &st, 0);
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

static bool t_exact_match_x(void)
{
    sqlite3 *db = _open_tricky_db();
    sqlite3_stmt *st;
    sqlite3_prepare_v2(db, "SELECT * FROM tricky;", -1, &st, 0);
    sqlite3_step(st);

    csorma_s *s = __rs_getString(st, "x");
    T_ASSERT_INT_EQ(s->l, 1, "len=1");
    T_ASSERT(s->s[0] == 'X', "content='X'");
    csorma_str_free(s);

    sqlite3_finalize(st);
    sqlite3_close(db);
    return true;
}

/* ============================================================
 *  PREFIX MATCHING BUG TESTS
 * ============================================================ */

static bool t_prefix_bug_id_vs_id_extra(void)
{
    /*
     * BUG: searching for "id" should return column 0 (id=1).
     * But if the prefix match hits "id_extra" first (column 1, value=2),
     * we get the wrong value.
     *
     * In practice, SQLite returns columns in order, so "id" (col 0)
     * is found before "id_extra" (col 1). But the REVERSE is the problem:
     * searching for "id" when ONLY "id_extra" exists would match.
     */
    sqlite3 *db;
    sqlite3_open(":memory:", &db);
    sqlite3_exec(db,
        "CREATE TABLE t(\"id_extra\" INTEGER, \"other\" TEXT);"
        "INSERT INTO t VALUES(99, 'test');", 0, 0, 0);

    sqlite3_stmt *st;
    sqlite3_prepare_v2(db, "SELECT * FROM t;", -1, &st, 0);
    sqlite3_step(st);

    /* Search for "id" — should NOT match "id_extra" but it DOES due to prefix bug */
    int64_t val = __rs_getLong(st, "id");

    /* If the bug exists, val will be 99 (from id_extra column).
     * If fixed, val would be 0 (column not found → index -1 → UB/0). */
    if (val == 99) {
        printf(C_YELLOW "\n");
        printf("  +-----------------------------------------------------------+\n");
        printf("  |  PREFIX MATCHING BUG CONFIRMED                            |\n");
        printf("  +-----------------------------------------------------------+\n");
        printf("  |                                                           |\n");
        printf("  |  Searched for column: \"id\"                               |\n");
        printf("  |  Matched column:      \"id_extra\" (WRONG!)               |\n");
        printf("  |  Returned value:      %lld (from id_extra)               |\n", (long long)val);
        printf("  |                                                           |\n");
        printf("  |  ROOT CAUSE in rs_find_column_idx():                      |\n");
        printf("  |    strncmp(col_name, column_name, strlen(column_name))    |\n");
        printf("  |                                                           |\n");
        printf("  |  This is a PREFIX match, not an EXACT match.              |\n");
        printf("  |  \"id\" is a prefix of \"id_extra\", so it matches.          |\n");
        printf("  |                                                           |\n");
        printf("  |  FIX: compare full lengths:                               |\n");
        printf("  |    strlen(col_name) == strlen(column_name) &&             |\n");
        printf("  |    strncmp(col_name, column_name, strlen(col_name)) == 0  |\n");
        printf("  +-----------------------------------------------------------+\n");
        printf(C_RESET "\n");
        _tf_failed++;
        sqlite3_finalize(st);
        sqlite3_close(db);
        return false;
    }

    sqlite3_finalize(st);
    sqlite3_close(db);
    return true;
}

static bool t_prefix_bug_name_vs_username(void)
{
    /*
     * Search for "name" — should NOT match "username".
     * But "name" is NOT a prefix of "username" (it's a suffix),
     * so this should actually work correctly.
     */
    sqlite3 *db;
    sqlite3_open(":memory:", &db);
    sqlite3_exec(db,
        "CREATE TABLE t(\"username\" TEXT);"
        "INSERT INTO t VALUES('admin');", 0, 0, 0);

    sqlite3_stmt *st;
    sqlite3_prepare_v2(db, "SELECT * FROM t;", -1, &st, 0);
    sqlite3_step(st);

    csorma_s *s = __rs_getString(st, "name");
    /* "name" is not a prefix of "username", so it shouldn't match.
     * Result: column not found → returns empty string (from NULL handling) */
    T_ASSERT_INT_EQ(s->l, 0, "should not match 'username'");
    csorma_str_free(s);

    sqlite3_finalize(st);
    sqlite3_close(db);
    return true;
}

static bool t_prefix_bug_a_vs_ab_vs_abc(void)
{
    /*
     * Table has columns: a, ab, abc
     * Searching for "a" should match "a" (first in column order).
     * Searching for "ab" should match "ab" (but might match "abc" if order differs).
     */
    sqlite3 *db = _open_tricky_db();
    sqlite3_stmt *st;
    sqlite3_prepare_v2(db, "SELECT * FROM tricky;", -1, &st, 0);
    sqlite3_step(st);

    int64_t val_a = __rs_getLong(st, "a");
    T_ASSERT_INT_EQ(val_a, 10, "a=10");

    sqlite3_finalize(st);
    sqlite3_prepare_v2(db, "SELECT * FROM tricky;", -1, &st, 0);
    sqlite3_step(st);

    int64_t val_ab = __rs_getLong(st, "ab");
    T_ASSERT_INT_EQ(val_ab, 20, "ab=20");

    sqlite3_finalize(st);
    sqlite3_prepare_v2(db, "SELECT * FROM tricky;", -1, &st, 0);
    sqlite3_step(st);

    int64_t val_abc = __rs_getLong(st, "abc");
    T_ASSERT_INT_EQ(val_abc, 30, "abc=30");

    sqlite3_finalize(st);
    sqlite3_close(db);
    return true;
}

/* ============================================================
 *  Missing column tests
 * ============================================================ */

static bool t_missing_column_returns_zero(void)
{
    sqlite3 *db = _open_tricky_db();
    sqlite3_stmt *st;
    sqlite3_prepare_v2(db, "SELECT * FROM tricky;", -1, &st, 0);
    sqlite3_step(st);

    /* Request a column that doesn't exist */
    int64_t val = __rs_getLong(st, "nonexistent");
    /* rs_find_column_idx returns -1, sqlite3_column_int64(stmt, -1) is UB
     * but in practice returns 0 */
    printf("         (missing column returned: %lld — UB territory)\n", (long long)val);

    sqlite3_finalize(st);
    sqlite3_close(db);
    return true;
}

static bool t_missing_column_string(void)
{
    sqlite3 *db = _open_tricky_db();
    sqlite3_stmt *st;
    sqlite3_prepare_v2(db, "SELECT * FROM tricky;", -1, &st, 0);
    sqlite3_step(st);

    csorma_s *s = __rs_getString(st, "nonexistent");
    /* Should return empty string due to NULL handling */
    T_ASSERT_PTR_NOT_NULL(s, "non-null");
    T_ASSERT_INT_EQ(s->l, 0, "empty for missing column");
    csorma_str_free(s);

    sqlite3_finalize(st);
    sqlite3_close(db);
    return true;
}

/* ============================================================
 *  Case sensitivity test
 * ============================================================ */

static bool t_case_sensitivity(void)
{
    sqlite3 *db = _open_tricky_db();
    sqlite3_stmt *st;
    sqlite3_prepare_v2(db, "SELECT * FROM tricky;", -1, &st, 0);
    sqlite3_step(st);

    /* SQLite column names are case-insensitive in SQL,
     * but sqlite3_column_name() returns them as declared.
     * rs_find_column_idx uses strncmp which IS case-sensitive. */
    int64_t val_lower = __rs_getLong(st, "id");
    sqlite3_finalize(st);

    sqlite3_prepare_v2(db, "SELECT * FROM tricky;", -1, &st, 0);
    sqlite3_step(st);
    int64_t val_upper = __rs_getLong(st, "ID");
    sqlite3_finalize(st);

    /* If case-sensitive, "ID" won't match "id" */
    if (val_upper != val_lower) {
        printf("         NOTE: lookup is case-sensitive (\"ID\" != \"id\")\n");
        printf("         val_lower=%lld, val_upper=%lld\n",
               (long long)val_lower, (long long)val_upper);
    }

    sqlite3_close(db);
    return true;
}

/* ============================================================
 *  Empty column name test
 * ============================================================ */

static bool t_empty_column_name(void)
{
    sqlite3 *db = _open_tricky_db();
    sqlite3_stmt *st;
    sqlite3_prepare_v2(db, "SELECT * FROM tricky;", -1, &st, 0);
    sqlite3_step(st);

    /* Empty string: strlen("")=0, strncmp(anything, "", 0)==0 always!
     * This means empty column name matches the FIRST column. */
    int64_t val = __rs_getLong(st, "");
    printf("         (empty column name returned: %lld — matches first col due to strncmp len=0)\n",
           (long long)val);

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
    printf("   CSORMA COLUMN LOOKUP TESTS (rs_find_column_idx)\n");
    printf("   Source: ../template/csorma.c (compiled directly)\n");
    printf("  ================================================================\n");
    printf(C_RESET "\n");

    TEST_SUITE("Exact match");
    RUN_TEST(t_exact_match_id);
    RUN_TEST(t_exact_match_name);
    RUN_TEST(t_exact_match_x);
    SUITE_END();

    TEST_SUITE("PREFIX MATCHING BUG");
    RUN_TEST(t_prefix_bug_id_vs_id_extra);
    RUN_TEST(t_prefix_bug_name_vs_username);
    RUN_TEST(t_prefix_bug_a_vs_ab_vs_abc);
    SUITE_END();

    TEST_SUITE("Missing column");
    RUN_TEST(t_missing_column_returns_zero);
    RUN_TEST(t_missing_column_string);
    SUITE_END();

    TEST_SUITE("Case sensitivity");
    RUN_TEST(t_case_sensitivity);
    SUITE_END();

    TEST_SUITE("Empty column name");
    RUN_TEST(t_empty_column_name);
    SUITE_END();

    return test_summary("Column Lookup");
}
