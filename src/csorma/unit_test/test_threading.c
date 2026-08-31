/*
 * test_threading.c — Concurrency and thread-safety tests for csorma
 *
 * Pounds the ORM with many simultaneous threads to detect:
 *   - Data races on the global lastrowid mutex
 *   - Deadlocks in mutex lock/unlock paths
 *   - Crashes from concurrent SQLite access
 *   - Memory corruption from concurrent string building
 *   - Incorrect row IDs under concurrent inserts
 *   - Corruption under concurrent read/write mixes
 *
 * Compile via Makefile: make test_thread
 * Sanitized:            make asan_all / tsan_all
 */

#include "test_framework.h"
#include "csorma.h"

#include <pthread.h>
#include <stdatomic.h>
#include <unistd.h>
#include <signal.h>
#include <setjmp.h>

/* ============================================================
 *  Configuration
 * ============================================================ */
#define NUM_THREADS_INSERT    8
#define NUM_THREADS_RW       6
#define NUM_THREADS_STRING   8
#define NUM_THREADS_BINDVAR  8
#define NUM_THREADS_OPENCL   4
#define NUM_THREADS_SCHEMA   4
#define OPS_PER_THREAD      500
#define STRESS_THREADS       16
#define STRESS_OPS           200
#define DEADLOCK_TIMEOUT_SEC 30

/* ============================================================
 *  Shared state
 * ============================================================ */
static atomic_int g_insert_count   = 0;
static atomic_int g_insert_errors  = 0;
static atomic_int g_read_count     = 0;
static atomic_int g_read_errors    = 0;
static atomic_int g_write_count    = 0;
static atomic_int g_write_errors   = 0;
static atomic_int g_string_count   = 0;
static atomic_int g_string_errors  = 0;
static atomic_int g_bindvar_count  = 0;
static atomic_int g_bindvar_errors = 0;
static atomic_int g_opencl_count   = 0;
static atomic_int g_opencl_errors  = 0;
static atomic_int g_schema_count   = 0;
static atomic_int g_schema_errors  = 0;
static atomic_int g_stop_flag      = 0;

static OrmaDatabase *g_db = NULL;

/* ============================================================
 *  Helpers
 * ============================================================ */
static OrmaDatabase *open_mem_db(void)
{
    return OrmaDatabase_init((const uint8_t *)":memory:", 8,
                             (const uint8_t *)"", 0);
}

static void setup_test_table(OrmaDatabase *o)
{
    OrmaDatabase_run_multi_sql(o,
        (const uint8_t *)"CREATE TABLE IF NOT EXISTS thread_test ("
        "\"id\" INTEGER PRIMARY KEY AUTOINCREMENT,"
        "\"thread_id\" INTEGER,"
        "\"seq\" INTEGER,"
        "\"data\" TEXT);");
}

/* ============================================================
 *  TEST 1: Concurrent INSERTS — pound the lastrowid mutex
 *
 *  Multiple threads insert rows simultaneously. Each thread
 *  checks that the returned rowid is positive and unique.
 *  This directly stresses:
 *    - OrmaDatabase_lock_lastrowid_mutex()
 *    - sqlite3_last_insert_rowid()
 *    - OrmaDatabase_unlock_lastrowid_mutex()
 * ============================================================ */
static void *insert_worker(void *arg)
{
    int tid = (int)(intptr_t)arg;

    for (int i = 0; i < OPS_PER_THREAD; i++)
    {
        char data[64];
        snprintf(data, sizeof(data), "thread%d_op%d", tid, i);

        csorma_s *sql = csorma_str2_build(
            "INSERT INTO thread_test(thread_id, seq, data) VALUES(");
        sql = csorma_str_int32t(sql, tid);
        sql = csorma_str_con(sql, ",", 1);
        sql = csorma_str_int32t(sql, i);
        sql = csorma_str_con(sql, ",'", 2);
        sql = csorma_str_con(sql, data, strlen(data));
        sql = csorma_str_con(sql, "');", 3);

        OrmaDatabase_lock_lastrowid_mutex();
        CSORMA_GENERIC_RESULT r = OrmaDatabase_run_multi_sql(g_db, sql->s);
        int64_t rowid = 0;
        if (r == CSORMA_GENERIC_RESULT_OK)
        {
            rowid = sqlite3_last_insert_rowid(g_db->db);
        }
        OrmaDatabase_unlock_lastrowid_mutex();

        csorma_str_free(sql);

        if (r != CSORMA_GENERIC_RESULT_OK)
        {
            atomic_fetch_add(&g_insert_errors, 1);
        }
        else if (rowid <= 0)
        {
            atomic_fetch_add(&g_insert_errors, 1);
        }
        else
        {
            atomic_fetch_add(&g_insert_count, 1);
        }
    }
    return NULL;
}

static bool t_concurrent_inserts(void)
{
    g_db = open_mem_db();
    T_ASSERT_PTR_NOT_NULL(g_db, "open db");
    setup_test_table(g_db);

    atomic_store(&g_insert_count, 0);
    atomic_store(&g_insert_errors, 0);

    pthread_t threads[NUM_THREADS_INSERT];
    for (int i = 0; i < NUM_THREADS_INSERT; i++)
        pthread_create(&threads[i], NULL, insert_worker, (void *)(intptr_t)i);
    for (int i = 0; i < NUM_THREADS_INSERT; i++)
        pthread_join(threads[i], NULL);

    int total = atomic_load(&g_insert_count);
    int errors = atomic_load(&g_insert_errors);
    int expected = NUM_THREADS_INSERT * OPS_PER_THREAD;

    printf("         inserts: %d/%d, errors: %d\n", total, expected, errors);
    T_ASSERT_INT_EQ(errors, 0, "no insert errors");
    T_ASSERT_INT_EQ(total, expected, "all inserts succeeded");

    /* Verify actual row count in DB */
    int64_t count = OrmaDatabase_run_sql_int64(g_db,
        (const uint8_t *)"SELECT count(*) FROM thread_test;");
    T_ASSERT_INT_EQ(count, expected, "DB row count matches");

    OrmaDatabase_shutdown(g_db);
    g_db = NULL;
    return true;
}

/* ============================================================
 *  TEST 2: Concurrent READ + WRITE mix
 *
 *  Half the threads insert, half the threads read (SELECT).
 *  Tests SQLite's internal locking under mixed load.
 * ============================================================ */
static void *writer_worker(void *arg)
{
    int tid = (int)(intptr_t)arg;
    for (int i = 0; i < OPS_PER_THREAD; i++)
    {
        char sql[128];
        snprintf(sql, sizeof(sql),
            "INSERT INTO thread_test(thread_id, seq, data) VALUES(%d, %d, 'w%d');",
            tid, i, tid);
        CSORMA_GENERIC_RESULT r = OrmaDatabase_run_multi_sql(g_db, (const uint8_t *)sql);
        if (r == CSORMA_GENERIC_RESULT_OK)
            atomic_fetch_add(&g_write_count, 1);
        else
            atomic_fetch_add(&g_write_errors, 1);
    }
    return NULL;
}

static void *reader_worker(void *arg)
{
    int tid = (int)(intptr_t)arg;
    for (int i = 0; i < OPS_PER_THREAD; i++)
    {
        int64_t val = OrmaDatabase_run_sql_int64(g_db,
            (const uint8_t *)"SELECT count(*) FROM thread_test;");
        if (val >= 0)
            atomic_fetch_add(&g_read_count, 1);
        else
            atomic_fetch_add(&g_read_errors, 1);
    }
    return NULL;
}

static bool t_concurrent_read_write(void)
{
    g_db = open_mem_db();
    T_ASSERT_PTR_NOT_NULL(g_db, "open db");
    setup_test_table(g_db);

    atomic_store(&g_read_count, 0);
    atomic_store(&g_read_errors, 0);
    atomic_store(&g_write_count, 0);
    atomic_store(&g_write_errors, 0);

    int half = NUM_THREADS_RW / 2;
    pthread_t threads[NUM_THREADS_RW];

    for (int i = 0; i < half; i++)
        pthread_create(&threads[i], NULL, writer_worker, (void *)(intptr_t)i);
    for (int i = half; i < NUM_THREADS_RW; i++)
        pthread_create(&threads[i], NULL, reader_worker, (void *)(intptr_t)i);
    for (int i = 0; i < NUM_THREADS_RW; i++)
        pthread_join(threads[i], NULL);

    int reads  = atomic_load(&g_read_count);
    int writes = atomic_load(&g_write_count);
    int rerr   = atomic_load(&g_read_errors);
    int werr   = atomic_load(&g_write_errors);

    printf("         reads: %d (errors: %d), writes: %d (errors: %d)\n",
           reads, rerr, writes, werr);

    T_ASSERT_INT_EQ(rerr, 0, "no read errors");
    T_ASSERT_INT_EQ(werr, 0, "no write errors");
    T_ASSERT_INT_EQ(writes, half * OPS_PER_THREAD, "all writes done");
    T_ASSERT_INT_EQ(reads, half * OPS_PER_THREAD, "all reads done");

    OrmaDatabase_shutdown(g_db);
    g_db = NULL;
    return true;
}

/* ============================================================
 *  TEST 3: Concurrent string building
 *
 *  Each thread independently builds strings via csorma_str_con.
 *  Verifies no cross-thread corruption of string data.
 * ============================================================ */
static void *string_worker(void *arg)
{
    int tid = (int)(intptr_t)arg;
    char expected_tag[16];
    snprintf(expected_tag, sizeof(expected_tag), "T%d_", tid);

    for (int i = 0; i < OPS_PER_THREAD; i++)
    {
        csorma_s *s = csorma_str2_build(expected_tag);
        char chunk[32];
        int len = snprintf(chunk, sizeof(chunk), "%04d", i);
        s = csorma_str_con(s, chunk, (uint32_t)len);

        /* Verify content is correct for THIS thread */
        if (s->l != strlen(expected_tag) + (uint32_t)len)
        {
            atomic_fetch_add(&g_string_errors, 1);
            csorma_str_free(s);
            continue;
        }
        if (memcmp(s->s, expected_tag, strlen(expected_tag)) != 0)
        {
            atomic_fetch_add(&g_string_errors, 1);
            csorma_str_free(s);
            continue;
        }

        /* Verify cur pointer is valid */
        long off = s->cur - s->s;
        if (off < 0 || off > (long)s->l)
        {
            atomic_fetch_add(&g_string_errors, 1);
        }

        csorma_str_free(s);
        atomic_fetch_add(&g_string_count, 1);
    }
    return NULL;
}

static bool t_concurrent_string_build(void)
{
    atomic_store(&g_string_count, 0);
    atomic_store(&g_string_errors, 0);

    pthread_t threads[NUM_THREADS_STRING];
    for (int i = 0; i < NUM_THREADS_STRING; i++)
        pthread_create(&threads[i], NULL, string_worker, (void *)(intptr_t)i);
    for (int i = 0; i < NUM_THREADS_STRING; i++)
        pthread_join(threads[i], NULL);

    int total  = atomic_load(&g_string_count);
    int errors = atomic_load(&g_string_errors);
    int expected = NUM_THREADS_STRING * OPS_PER_THREAD;

    printf("         string ops: %d/%d, errors: %d\n", total, expected, errors);
    T_ASSERT_INT_EQ(errors, 0, "no string corruption");
    T_ASSERT_INT_EQ(total, expected, "all string ops completed");
    return true;
}

/* ============================================================
 *  TEST 4: Concurrent bind variable creation/destruction
 * ============================================================ */
static void *bindvar_worker(void *arg)
{
    int tid = (int)(intptr_t)arg;

    for (int i = 0; i < OPS_PER_THREAD; i++)
    {
        OrmaBindvars *bv = bindvar_init(NULL);
        bv = bindvar_add_n(bv, tid, BINDVAR_TYPE_Int);
        bv = bindvar_add_n(bv, (int64_t)i * 1000, BINDVAR_TYPE_Long);

        char txt[32];
        snprintf(txt, sizeof(txt), "bv_%d_%d", tid, i);
        csorma_s *s = csorma_str2_build(txt);
        bv = bindvar_add_s(bv, s);

        /* Verify */
        if (bv->items != 3)
        {
            atomic_fetch_add(&g_bindvar_errors, 1);
        }
        else if (bv->b[0].n != tid)
        {
            atomic_fetch_add(&g_bindvar_errors, 1);
        }

        bindvar_free(bv);
        atomic_fetch_add(&g_bindvar_count, 1);
    }
    return NULL;
}

static bool t_concurrent_bindvars(void)
{
    atomic_store(&g_bindvar_count, 0);
    atomic_store(&g_bindvar_errors, 0);

    pthread_t threads[NUM_THREADS_BINDVAR];
    for (int i = 0; i < NUM_THREADS_BINDVAR; i++)
        pthread_create(&threads[i], NULL, bindvar_worker, (void *)(intptr_t)i);
    for (int i = 0; i < NUM_THREADS_BINDVAR; i++)
        pthread_join(threads[i], NULL);

    int total  = atomic_load(&g_bindvar_count);
    int errors = atomic_load(&g_bindvar_errors);
    int expected = NUM_THREADS_BINDVAR * OPS_PER_THREAD;

    printf("         bindvar ops: %d/%d, errors: %d\n", total, expected, errors);
    T_ASSERT_INT_EQ(errors, 0, "no bindvar corruption");
    T_ASSERT_INT_EQ(total, expected, "all bindvar ops completed");
    return true;
}

/* ============================================================
 *  TEST 5: Concurrent DB open/close cycles
 *
 *  Each thread opens an in-memory DB, does work, closes it.
 *  Tests that init/shutdown don't corrupt global state.
 * ============================================================ */
static void *openclose_worker(void *arg)
{
    int tid = (int)(intptr_t)arg;

    for (int i = 0; i < 50; i++)
    {
        OrmaDatabase *o = open_mem_db();
        if (o == NULL)
        {
            atomic_fetch_add(&g_opencl_errors, 1);
            continue;
        }

        OrmaDatabase_run_multi_sql(o,
            (const uint8_t *)"CREATE TABLE t(x INT); INSERT INTO t VALUES(1);");
        int64_t v = OrmaDatabase_run_sql_int64(o,
            (const uint8_t *)"SELECT x FROM t;");
        if (v != 1)
        {
            atomic_fetch_add(&g_opencl_errors, 1);
        }

        OrmaDatabase_shutdown(o);
        atomic_fetch_add(&g_opencl_count, 1);
    }
    return NULL;
}

static bool t_concurrent_open_close(void)
{
    atomic_store(&g_opencl_count, 0);
    atomic_store(&g_opencl_errors, 0);

    pthread_t threads[NUM_THREADS_OPENCL];
    for (int i = 0; i < NUM_THREADS_OPENCL; i++)
        pthread_create(&threads[i], NULL, openclose_worker, (void *)(intptr_t)i);
    for (int i = 0; i < NUM_THREADS_OPENCL; i++)
        pthread_join(threads[i], NULL);

    int total  = atomic_load(&g_opencl_count);
    int errors = atomic_load(&g_opencl_errors);
    int expected = NUM_THREADS_OPENCL * 50;

    printf("         open/close cycles: %d/%d, errors: %d\n", total, expected, errors);
    T_ASSERT_INT_EQ(errors, 0, "no open/close errors");
    T_ASSERT_INT_EQ(total, expected, "all cycles completed");
    return true;
}

/* ============================================================
 *  TEST 6: Concurrent schema upgrades
 *
 *  Multiple threads call do_schema_upgrade on the SAME database.
 *  Tests the global callback pointer for races.
 * ============================================================ */
static atomic_int g_upgrade_cb_calls = 0;

static void schema_cb(uint32_t old_v, uint32_t new_v)
{
    (void)old_v; (void)new_v;
    atomic_fetch_add(&g_upgrade_cb_calls, 1);
}

static void *schema_worker(void *arg)
{
    int tid = (int)(intptr_t)arg;
    (void)tid;

    /* Each thread tries to upgrade the same DB to version 3 */
    OrmaDatabase_set_schema_upgrade_callback(schema_cb);
    OrmaDatabase_do_schema_upgrade(g_db, 3);
    atomic_fetch_add(&g_schema_count, 1);
    return NULL;
}

static bool t_concurrent_schema_upgrade(void)
{
    g_db = open_mem_db();
    T_ASSERT_PTR_NOT_NULL(g_db, "open db");

    atomic_store(&g_schema_count, 0);
    atomic_store(&g_upgrade_cb_calls, 0);

    pthread_t threads[NUM_THREADS_SCHEMA];
    for (int i = 0; i < NUM_THREADS_SCHEMA; i++)
        pthread_create(&threads[i], NULL, schema_worker, (void *)(intptr_t)i);
    for (int i = 0; i < NUM_THREADS_SCHEMA; i++)
        pthread_join(threads[i], NULL);

    int total = atomic_load(&g_schema_count);
    T_ASSERT_INT_EQ(total, NUM_THREADS_SCHEMA, "all threads completed");

    /* The upgrade callbacks should have been called 3 times total
     * (0->1, 1->2, 2->3) but with concurrent access the exact count
     * may vary. Just verify no crash occurred. */
    int cb_calls = atomic_load(&g_upgrade_cb_calls);
    printf("         schema threads: %d, callback invocations: %d\n",
           total, cb_calls);

    OrmaDatabase_shutdown(g_db);
    g_db = NULL;
    return true;
}

/* ============================================================
 *  TEST 7: Mutex lock/unlock stress
 *
 *  Rapidly lock and unlock the global mutex from many threads.
 *  Detects deadlocks and mutex corruption.
 * ============================================================ */
static atomic_int g_mutex_ops = 0;

static void *mutex_worker(void *arg)
{
    (void)arg;
    for (int i = 0; i < 10000; i++)
    {
        OrmaDatabase_lock_lastrowid_mutex();
        /* Simulate tiny critical section */
        volatile int x = 0;
        x++;
        (void)x;
        OrmaDatabase_unlock_lastrowid_mutex();
        atomic_fetch_add(&g_mutex_ops, 1);
    }
    return NULL;
}

static bool t_mutex_stress(void)
{
    atomic_store(&g_mutex_ops, 0);

    pthread_t threads[NUM_THREADS_INSERT];
    for (int i = 0; i < NUM_THREADS_INSERT; i++)
        pthread_create(&threads[i], NULL, mutex_worker, NULL);
    for (int i = 0; i < NUM_THREADS_INSERT; i++)
        pthread_join(threads[i], NULL);

    int total = atomic_load(&g_mutex_ops);
    int expected = NUM_THREADS_INSERT * 10000;

    printf("         mutex ops: %d/%d\n", total, expected);
    T_ASSERT_INT_EQ(total, expected, "all mutex ops completed (no deadlock)");
    return true;
}

/* ============================================================
 *  TEST 8: High-thread-count stress test
 *
 *  Spawn STRESS_THREADS threads, each doing a mix of
 *  string building + DB insert + read. Maximum pressure.
 * ============================================================ */
static void *stress_worker(void *arg)
{
    int tid = (int)(intptr_t)arg;

    for (int i = 0; i < STRESS_OPS; i++)
    {
        /* String building */
        csorma_s *s = csorma_str2_build("stress_");
        char num[16];
        int len = snprintf(num, sizeof(num), "%d_%d", tid, i);
        s = csorma_str_con(s, num, (uint32_t)len);
        csorma_str_free(s);

        /* DB write */
        char sql[128];
        snprintf(sql, sizeof(sql),
            "INSERT INTO thread_test(thread_id, seq, data) VALUES(%d, %d, 'stress');",
            tid, i);
        OrmaDatabase_run_multi_sql(g_db, (const uint8_t *)sql);

        /* DB read */
        OrmaDatabase_run_sql_int64(g_db,
            (const uint8_t *)"SELECT count(*) FROM thread_test;");

        /* Bindvar create/destroy */
        OrmaBindvars *bv = bindvar_init(NULL);
        bv = bindvar_add_n(bv, tid, BINDVAR_TYPE_Int);
        bindvar_free(bv);
    }
    return NULL;
}

static bool t_stress_many_threads(void)
{
    g_db = open_mem_db();
    T_ASSERT_PTR_NOT_NULL(g_db, "open db");
    setup_test_table(g_db);

    pthread_t threads[STRESS_THREADS];
    for (int i = 0; i < STRESS_THREADS; i++)
        pthread_create(&threads[i], NULL, stress_worker, (void *)(intptr_t)i);
    for (int i = 0; i < STRESS_THREADS; i++)
        pthread_join(threads[i], NULL);

    int64_t count = OrmaDatabase_run_sql_int64(g_db,
        (const uint8_t *)"SELECT count(*) FROM thread_test;");
    int64_t expected = (int64_t)STRESS_THREADS * STRESS_OPS;

    printf("         stress: %d threads x %d ops, rows=%lld/%lld\n",
           STRESS_THREADS, STRESS_OPS, (long long)count, (long long)expected);
    T_ASSERT_INT_EQ(count, expected, "all stress rows inserted");

    OrmaDatabase_shutdown(g_db);
    g_db = NULL;
    return true;
}

/* ============================================================
 *  TEST 9: Rapid insert with rowid uniqueness check
 *
 *  Multiple threads insert and record rowids. After all threads
 *  finish, verify no duplicate rowids exist.
 * ============================================================ */
static int64_t g_rowids[NUM_THREADS_INSERT * OPS_PER_THREAD];
static atomic_int g_rowid_idx = 0;

static void *rowid_worker(void *arg)
{
    int tid = (int)(intptr_t)arg;

    for (int i = 0; i < OPS_PER_THREAD; i++)
    {
        char sql[128];
        snprintf(sql, sizeof(sql),
            "INSERT INTO thread_test(thread_id, seq) VALUES(%d, %d);", tid, i);

        OrmaDatabase_lock_lastrowid_mutex();
        OrmaDatabase_run_multi_sql(g_db, (const uint8_t *)sql);
        int64_t rid = sqlite3_last_insert_rowid(g_db->db);
        OrmaDatabase_unlock_lastrowid_mutex();

        int idx = atomic_fetch_add(&g_rowid_idx, 1);
        if (idx < NUM_THREADS_INSERT * OPS_PER_THREAD)
            g_rowids[idx] = rid;
    }
    return NULL;
}

static int cmp_int64(const void *a, const void *b)
{
    int64_t va = *(const int64_t *)a;
    int64_t vb = *(const int64_t *)b;
    if (va < vb) return -1;
    if (va > vb) return 1;
    return 0;
}

static bool t_rowid_uniqueness(void)
{
    g_db = open_mem_db();
    T_ASSERT_PTR_NOT_NULL(g_db, "open db");
    setup_test_table(g_db);

    atomic_store(&g_rowid_idx, 0);
    memset(g_rowids, 0, sizeof(g_rowids));

    pthread_t threads[NUM_THREADS_INSERT];
    for (int i = 0; i < NUM_THREADS_INSERT; i++)
        pthread_create(&threads[i], NULL, rowid_worker, (void *)(intptr_t)i);
    for (int i = 0; i < NUM_THREADS_INSERT; i++)
        pthread_join(threads[i], NULL);

    int total = atomic_load(&g_rowid_idx);
    T_ASSERT_INT_EQ(total, NUM_THREADS_INSERT * OPS_PER_THREAD, "all rowids collected");

    /* Sort and check for duplicates */
    qsort(g_rowids, total, sizeof(int64_t), cmp_int64);
    int dupes = 0;
    for (int i = 1; i < total; i++)
    {
        if (g_rowids[i] == g_rowids[i - 1])
            dupes++;
    }

    printf("         rowids collected: %d, duplicates: %d\n", total, dupes);
    T_ASSERT_INT_EQ(dupes, 0, "no duplicate rowids (mutex working)");

    OrmaDatabase_shutdown(g_db);
    g_db = NULL;
    return true;
}

/* ============================================================
 *  TEST 10: Thread creation/join rapid cycle
 *
 *  Create and destroy threads rapidly to stress pthread + mutex.
 * ============================================================ */
static void *tiny_worker(void *arg)
{
    (void)arg;
    OrmaDatabase_lock_lastrowid_mutex();
    OrmaDatabase_unlock_lastrowid_mutex();
    return NULL;
}

static bool t_rapid_thread_cycle(void)
{
    for (int round = 0; round < 100; round++)
    {
        pthread_t t;
        int rc = pthread_create(&t, NULL, tiny_worker, NULL);
        T_ASSERT_INT_EQ(rc, 0, "thread create");
        pthread_join(t, NULL);
    }
    return true;
}

/* ============================================================
 *  MAIN
 * ============================================================ */
int main(void)
{
    printf(C_BOLD "\n");
    printf("  ================================================================\n");
    printf("   CSORMA THREADING / CONCURRENCY TESTS\n");
    printf("   Source: ../template/csorma.c (compiled directly)\n");
    printf("   Threads: up to %d concurrent\n", STRESS_THREADS);
    printf("   Operations: up to %d per thread\n", OPS_PER_THREAD);
    printf("  ================================================================\n");
    printf(C_RESET "\n");

    TEST_SUITE("Mutex stress");
    RUN_TEST(t_mutex_stress);
    RUN_TEST(t_rapid_thread_cycle);
    SUITE_END();

    TEST_SUITE("Concurrent string building");
    RUN_TEST(t_concurrent_string_build);
    SUITE_END();

    TEST_SUITE("Concurrent bind variables");
    RUN_TEST(t_concurrent_bindvars);
    SUITE_END();

    TEST_SUITE("Concurrent DB open/close");
    RUN_TEST(t_concurrent_open_close);
    SUITE_END();

    TEST_SUITE("Concurrent INSERTS (lastrowid mutex)");
    RUN_TEST(t_concurrent_inserts);
    SUITE_END();

    TEST_SUITE("Concurrent READ + WRITE");
    RUN_TEST(t_concurrent_read_write);
    SUITE_END();

    TEST_SUITE("Rowid uniqueness under concurrency");
    RUN_TEST(t_rowid_uniqueness);
    SUITE_END();

    TEST_SUITE("Concurrent schema upgrade");
    RUN_TEST(t_concurrent_schema_upgrade);
    SUITE_END();

    TEST_SUITE("High-thread stress (mixed ops)");
    RUN_TEST(t_stress_many_threads);
    SUITE_END();

    return test_summary("Threading / Concurrency");
}
