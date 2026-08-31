/*
 * test_leaks.c — Memory lifecycle tests
 *
 * These tests exercise allocation/free patterns to verify no memory
 * is leaked. They are most useful when run under AddressSanitizer:
 *
 *   make asan_all
 *
 * ASAN will report any leaks at process exit. Without ASAN, these
 * tests verify that free() doesn't crash (double-free, corruption).
 *
 * Each test follows the pattern:
 *   1. Allocate resources through the normal API
 *   2. Use them (to ensure the allocation is "real")
 *   3. Free them through the normal API
 *   4. If ASAN is active, it checks for leaks at exit
 */

#include "test_framework.h"
#include "csorma.h"
#include "sqlite3.h"

#include <pthread.h>
#include <stdatomic.h>

/* ============================================================
 *  TEST 1: String build → concat → free
 *
 *  Verifies that csorma_str_free releases all memory allocated
 *  by csorma_str2_build and grown by csorma_str_con.
 * ============================================================ */

static bool t_leak_string_lifecycle(void)
{
    for (int round = 0; round < 100; round++)
    {
        csorma_s *s = csorma_str2_build("start_");
        for (int i = 0; i < 100; i++)
        {
            char chunk[32];
            int len = snprintf(chunk, sizeof(chunk), "chunk%d_", i);
            s = csorma_str_con(s, chunk, (uint32_t)len);
        }
        /* Verify content is meaningful (not freed early) */
        T_ASSERT(s->l > 600, "string grew");
        T_ASSERT(memcmp(s->s, "start_", 6) == 0, "prefix intact");
        csorma_str_free(s);
    }
    /* ASAN checks for leaks at exit */
    return true;
}

/* ============================================================
 *  TEST 2: String build with csorma_str_build (explicit length)
 * ============================================================ */

static bool t_leak_string_build_len(void)
{
    for (int round = 0; round < 100; round++)
    {
        /* Binary data with NUL bytes */
        char data[256];
        for (int i = 0; i < 256; i++) data[i] = (char)i;
        csorma_s *s = csorma_str_build(data, 256);
        T_ASSERT_INT_EQ(s->l, 256, "len");
        csorma_str_free(s);
    }
    return true;
}

/* ============================================================
 *  TEST 3: String con2 (two csorma_s)
 * ============================================================ */

static bool t_leak_string_con2(void)
{
    for (int round = 0; round < 100; round++)
    {
        csorma_s *a = csorma_str2_build("hello_");
        csorma_s *b = csorma_str2_build("world");
        a = csorma_str_con2(a, b);
        T_ASSERT_INT_EQ(a->l, 11, "len");
        csorma_str_free(a);
        csorma_str_free(b);
    }
    return true;
}

/* ============================================================
 *  TEST 4: String int32t repeated append
 * ============================================================ */

static bool t_leak_string_int32t(void)
{
    for (int round = 0; round < 100; round++)
    {
        csorma_s *s = csorma_str2_build("");
        for (int i = -50; i < 50; i++)
        {
            s = csorma_str_int32t(s, i);
            s = csorma_str_con(s, ",", 1);
        }
        T_ASSERT(s->l > 100, "grew");
        csorma_str_free(s);
    }
    return true;
}

/* ============================================================
 *  TEST 5: Bindvar lifecycle
 * ============================================================ */

static bool t_leak_bindvar_lifecycle(void)
{
    for (int round = 0; round < 100; round++)
    {
        OrmaBindvars *bv = bindvar_init(NULL);

        /* Add integers */
        for (int i = 0; i < 20; i++)
            bv = bindvar_add_n(bv, i * 100, BINDVAR_TYPE_Int);

        /* Add longs */
        for (int i = 0; i < 10; i++)
            bv = bindvar_add_n(bv, (int64_t)i * 1000000000LL, BINDVAR_TYPE_Long);

        /* Add booleans */
        bv = bindvar_add_n(bv, 1, BINDVAR_TYPE_Boolean);
        bv = bindvar_add_n(bv, 0, BINDVAR_TYPE_Boolean);

        /* Add strings */
        for (int i = 0; i < 10; i++)
        {
            char txt[32];
            snprintf(txt, sizeof(txt), "str_%d", i);
            csorma_s *s = csorma_str2_build(txt);
            bv = bindvar_add_s(bv, s);
        }

        T_ASSERT_INT_EQ(bv->items, 42, "42 items");
        bindvar_free(bv);
    }
    return true;
}

/* ============================================================
 *  TEST 6: Bindvar with NULL strings
 * ============================================================ */

static bool t_leak_bindvar_null_strings(void)
{
    for (int round = 0; round < 100; round++)
    {
        OrmaBindvars *bv = bindvar_init(NULL);
        for (int i = 0; i < 20; i++)
            bv = bindvar_add_s(bv, NULL);
        T_ASSERT_INT_EQ(bv->items, 20, "20 NULL strings");
        bindvar_free(bv);
    }
    return true;
}

/* ============================================================
 *  TEST 7: Database init/shutdown cycle
 *
 *  Repeatedly open and close in-memory databases.
 *  ASAN will detect sqlite3 connection leaks.
 * ============================================================ */

static bool t_leak_db_lifecycle(void)
{
    for (int round = 0; round < 50; round++)
    {
        OrmaDatabase *o = OrmaDatabase_init(
            (const uint8_t *)":memory:", 8,
            (const uint8_t *)"", 0);
        T_ASSERT_PTR_NOT_NULL(o, "open");

        OrmaDatabase_run_multi_sql(o,
            (const uint8_t *)"CREATE TABLE t(id INTEGER, val TEXT);");
        OrmaDatabase_run_multi_sql(o,
            (const uint8_t *)"INSERT INTO t VALUES(1, 'hello');");
        int64_t v = OrmaDatabase_run_sql_int64(o,
            (const uint8_t *)"SELECT id FROM t;");
        T_ASSERT_INT_EQ(v, 1, "read back");

        OrmaDatabase_shutdown(o);
    }
    return true;
}

/* ============================================================
 *  TEST 8: Full CRUD lifecycle
 *
 *  init → create table → insert → select → shutdown
 *  All resources should be freed at shutdown.
 * ============================================================ */

static bool t_leak_full_crud(void)
{
    for (int round = 0; round < 20; round++)
    {
        OrmaDatabase *o = OrmaDatabase_init(
            (const uint8_t *)":memory:", 8,
            (const uint8_t *)"", 0);

        OrmaDatabase_run_multi_sql(o,
            (const uint8_t *)"CREATE TABLE items("
            "id INTEGER PRIMARY KEY AUTOINCREMENT,"
            "name TEXT, score INTEGER, active BOOLEAN);");

        /* Insert many rows */
        for (int i = 0; i < 50; i++)
        {
            char sql[256];
            snprintf(sql, sizeof(sql),
                "INSERT INTO items(name, score, active) VALUES('item_%d', %d, %d);",
                i, i * 10, i % 2);
            OrmaDatabase_run_multi_sql(o, (const uint8_t *)sql);
        }

        /* Read back */
        int64_t count = OrmaDatabase_run_sql_int64(o,
            (const uint8_t *)"SELECT count(*) FROM items;");
        T_ASSERT_INT_EQ(count, 50, "50 rows");

        /* Update */
        OrmaDatabase_run_multi_sql(o,
            (const uint8_t *)"UPDATE items SET score = 999 WHERE active = 1;");

        /* Delete */
        OrmaDatabase_run_multi_sql(o,
            (const uint8_t *)"DELETE FROM items WHERE active = 0;");

        int64_t remaining = OrmaDatabase_run_sql_int64(o,
            (const uint8_t *)"SELECT count(*) FROM items;");
        T_ASSERT(remaining > 0 && remaining < 50, "some deleted");

        OrmaDatabase_shutdown(o);
    }
    return true;
}

/* ============================================================
 *  TEST 9: SQL clause building leak test
 *
 *  Repeatedly build WHERE/SET/ORDER BY clauses and free them.
 * ============================================================ */

static bool t_leak_sql_clause_building(void)
{
    for (int round = 0; round < 100; round++)
    {
        /* Build a WHERE clause */
        csorma_s *where_sql = csorma_str2_build(" WHERE 1=1 ");
        OrmaBindvars *where_bv = bindvar_init(NULL);

        for (int i = 0; i < 10; i++)
        {
            bind_to_where_sql_int(where_sql, where_bv,
                " AND \"col\" = ?", i, BINDVAR_TYPE_Int, " ");
        }

        csorma_s *val = csorma_str2_build("test_value");
        bind_to_where_sql_string(where_sql, where_bv,
            " AND \"name\" = ?", val, BINDVAR_TYPE_String, " ");

        /* Build a SET clause */
        csorma_s *set_sql = csorma_str2_build("");
        OrmaBindvars *set_bv = bindvar_init(NULL);

        bind_to_set_sql_int(set_sql, set_bv, "\"age\" = ?", 30, BINDVAR_TYPE_Int);
        csorma_s *set_val = csorma_str2_build("new_name");
        bind_to_set_sql_string(set_sql, set_bv, ", \"name\" = ?", set_val, BINDVAR_TYPE_String);

        /* Build an ORDER BY clause */
        csorma_s *order_sql = csorma_str2_build("");
        add_to_orderby_asc_sql(order_sql, "\"name\"", true);
        add_to_orderby_asc_sql(order_sql, "\"id\"", false);

        /* Free everything */
        csorma_str_free(where_sql);
        bindvar_free(where_bv);
        csorma_str_free(set_sql);
        bindvar_free(set_bv);
        csorma_str_free(order_sql);
    }
    return true;
}

/* ============================================================
 *  TEST 10: Schema upgrade leak test
 * ============================================================ */

static void _dummy_cb(uint32_t old_v, uint32_t new_v)
{
    (void)old_v;
    (void)new_v;
}

static bool t_leak_schema_upgrade(void)
{
    for (int round = 0; round < 20; round++)
    {
        OrmaDatabase *o = OrmaDatabase_init(
            (const uint8_t *)":memory:", 8,
            (const uint8_t *)"", 0);
        OrmaDatabase_set_schema_upgrade_callback(_dummy_cb);
        OrmaDatabase_do_schema_upgrade(o, 5);
        OrmaDatabase_shutdown(o);
    }
    return true;
}

/* ============================================================
 *  TEST 11: Result set reading leak test
 *
 *  __rs_getString allocates a csorma_s — make sure we free it.
 * ============================================================ */

static bool t_leak_resultset(void)
{
    for (int round = 0; round < 50; round++)
    {
        sqlite3 *db;
        sqlite3_open(":memory:", &db);
        sqlite3_exec(db,
            "CREATE TABLE t(id INTEGER, name TEXT);"
            "INSERT INTO t VALUES(1, 'hello');"
            "INSERT INTO t VALUES(2, 'world');"
            "INSERT INTO t VALUES(3, NULL);",
            0, 0, 0);

        sqlite3_stmt *st;
        sqlite3_prepare_v2(db, "SELECT * FROM t;", -1, &st, 0);

        while (sqlite3_step(st) == SQLITE_ROW)
        {
            int64_t id = __rs_getLong(st, "id");
            csorma_s *name = __rs_getString(st, "name");
            (void)id;

            /* __rs_getString allocates — we must free */
            csorma_str_free(name);
        }

        sqlite3_finalize(st);
        sqlite3_close(db);
    }
    return true;
}

/* ============================================================
 *  TEST 12: Concurrent string lifecycle (threaded leak test)
 * ============================================================ */

static void *leak_string_worker(void *arg)
{
    int tid = (int)(intptr_t)arg;
    for (int i = 0; i < 200; i++)
    {
        csorma_s *s = csorma_str2_build("thread_");
        char num[32];
        int len = snprintf(num, sizeof(num), "%d_%d_", tid, i);
        s = csorma_str_con(s, num, (uint32_t)len);

        /* Grow it more */
        for (int j = 0; j < 10; j++)
            s = csorma_str_con(s, "abcdefghij", 10);

        csorma_str_free(s);
    }
    return NULL;
}

static bool t_leak_concurrent_strings(void)
{
    pthread_t threads[4];
    for (int i = 0; i < 4; i++)
        pthread_create(&threads[i], NULL, leak_string_worker, (void *)(intptr_t)i);
    for (int i = 0; i < 4; i++)
        pthread_join(threads[i], NULL);
    /* ASAN checks at exit */
    return true;
}

/* ============================================================
 *  TEST 13: Concurrent bindvar lifecycle (threaded leak test)
 * ============================================================ */

static void *leak_bindvar_worker(void *arg)
{
    int tid = (int)(intptr_t)arg;
    for (int i = 0; i < 200; i++)
    {
        OrmaBindvars *bv = bindvar_init(NULL);
        bv = bindvar_add_n(bv, tid, BINDVAR_TYPE_Int);
        bv = bindvar_add_n(bv, (int64_t)i, BINDVAR_TYPE_Long);

        char txt[32];
        snprintf(txt, sizeof(txt), "bv_%d_%d", tid, i);
        csorma_s *s = csorma_str2_build(txt);
        bv = bindvar_add_s(bv, s);

        bindvar_free(bv);
    }
    return NULL;
}

static bool t_leak_concurrent_bindvars(void)
{
    pthread_t threads[4];
    for (int i = 0; i < 4; i++)
        pthread_create(&threads[i], NULL, leak_bindvar_worker, (void *)(intptr_t)i);
    for (int i = 0; i < 4; i++)
        pthread_join(threads[i], NULL);
    return true;
}

/* ============================================================
 *  TEST 14: Concurrent DB lifecycle (threaded leak test)
 * ============================================================ */

static void *leak_db_worker(void *arg)
{
    int tid = (int)(intptr_t)arg;
    (void)tid;
    for (int i = 0; i < 20; i++)
    {
        OrmaDatabase *o = OrmaDatabase_init(
            (const uint8_t *)":memory:", 8,
            (const uint8_t *)"", 0);
        if (o == NULL) continue;

        OrmaDatabase_run_multi_sql(o,
            (const uint8_t *)"CREATE TABLE t(x INT); INSERT INTO t VALUES(1);");
        OrmaDatabase_run_sql_int64(o,
            (const uint8_t *)"SELECT x FROM t;");
        OrmaDatabase_shutdown(o);
    }
    return NULL;
}

static bool t_leak_concurrent_db(void)
{
    pthread_t threads[4];
    for (int i = 0; i < 4; i++)
        pthread_create(&threads[i], NULL, leak_db_worker, (void *)(intptr_t)i);
    for (int i = 0; i < 4; i++)
        pthread_join(threads[i], NULL);
    return true;
}

/* ============================================================
 *  MAIN
 * ============================================================ */
int main(void)
{
    printf(C_BOLD "\n");
    printf("  ================================================================\n");
    printf("   CSORMA MEMORY LEAK LIFECYCLE TESTS\n");
    printf("   Source: ../template/csorma.c (compiled directly)\n");
    printf("   NOTE: Run with 'make asan_all' for full leak detection\n");
    printf("  ================================================================\n");
    printf(C_RESET "\n");

    TEST_SUITE("String lifecycle");
    RUN_TEST(t_leak_string_lifecycle);
    RUN_TEST(t_leak_string_build_len);
    RUN_TEST(t_leak_string_con2);
    RUN_TEST(t_leak_string_int32t);
    SUITE_END();

    TEST_SUITE("Bindvar lifecycle");
    RUN_TEST(t_leak_bindvar_lifecycle);
    RUN_TEST(t_leak_bindvar_null_strings);
    SUITE_END();

    TEST_SUITE("Database lifecycle");
    RUN_TEST(t_leak_db_lifecycle);
    RUN_TEST(t_leak_full_crud);
    SUITE_END();

    TEST_SUITE("SQL clause building lifecycle");
    RUN_TEST(t_leak_sql_clause_building);
    SUITE_END();

    TEST_SUITE("Schema upgrade lifecycle");
    RUN_TEST(t_leak_schema_upgrade);
    SUITE_END();

    TEST_SUITE("Result set lifecycle");
    RUN_TEST(t_leak_resultset);
    SUITE_END();

    TEST_SUITE("Concurrent lifecycle (threaded)");
    RUN_TEST(t_leak_concurrent_strings);
    RUN_TEST(t_leak_concurrent_bindvars);
    RUN_TEST(t_leak_concurrent_db);
    SUITE_END();

    return test_summary("Memory Leak Lifecycle");
}

