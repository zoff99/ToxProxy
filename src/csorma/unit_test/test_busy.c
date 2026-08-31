/*
 * test_busy.c — Tests for SQLITE_BUSY handling
 *
 * The _to_list() and OrmaDatabase_run_sql_int64() functions have
 * a SQLITE_BUSY spin loop:
 *
 *   else if (step == SQLITE_BUSY)
 *   {
 *       continue;  // busy wait, no sleep, no timeout
 *   }
 *
 * These tests verify behavior when two connections access the same
 * file-based database simultaneously (SQLITE_BUSY only occurs with
 * file databases, not :memory:).
 *
 * NOTE: These tests use file-based databases in /tmp/ which are
 * cleaned up after each test.
 */

#define _GNU_SOURCE

#include "test_framework.h"
#include "csorma.h"
#include "sqlite3.h"

#include <pthread.h>
#include <stdatomic.h>
#include <unistd.h>
#include <sys/time.h>
#include <unistd.h>
#include <signal.h>

#define BUSY_DB_DIR  "/tmp/"
#define BUSY_DB_NAME "_csorma_busy_test.db"
#define BUSY_DB_PATH BUSY_DB_DIR BUSY_DB_NAME

/* ============================================================
 *  Helpers
 * ============================================================ */

static void cleanup_busy_db(void)
{
    remove(BUSY_DB_PATH);
    remove(BUSY_DB_PATH "-journal");
    remove(BUSY_DB_PATH "-wal");
    remove(BUSY_DB_PATH "-shm");
}

static OrmaDatabase *open_file_db(void)
{
    return OrmaDatabase_init((const uint8_t *)BUSY_DB_DIR,
                             (uint32_t)strlen(BUSY_DB_DIR),
                             (const uint8_t *)BUSY_DB_NAME,
                             (uint32_t)strlen(BUSY_DB_NAME));
}

static void setup_busy_table(OrmaDatabase *o)
{
    OrmaDatabase_run_multi_sql(o,
        (const uint8_t *)"CREATE TABLE IF NOT EXISTS busy_test ("
        "\"id\" INTEGER PRIMARY KEY AUTOINCREMENT,"
        "\"value\" INTEGER);");
}

/* Helper: get current time in milliseconds */
static long long now_ms(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (long long)tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

/* ============================================================
 *  TEST 1: Two connections — writer holds lock, reader waits
 *
 *  Connection A starts a transaction and inserts rows (holds lock).
 *  Connection B tries to read. Without busy_timeout, connection B
 *  gets SQLITE_BUSY immediately. With busy_timeout, it waits.
 * ============================================================ */

static atomic_int g_writer_started  = 0;
static atomic_int g_writer_done     = 0;
static atomic_int g_reader_result   = 0;
static atomic_int g_reader_busy_hit = 0;

static void *busy_writer(void *arg)
{
    (void)arg;
    sqlite3 *db;
    sqlite3_open(BUSY_DB_PATH, &db);

    /* Hold a write lock by beginning a transaction and writing */
    sqlite3_exec(db, "BEGIN EXCLUSIVE;", 0, 0, 0);
    sqlite3_exec(db, "INSERT INTO busy_test(value) VALUES(1);", 0, 0, 0);

    /* Signal that we're holding the lock */
    atomic_store(&g_writer_started, 1);

    /* Hold the lock for a short time */
    usleep(200 * 1000); /* 200ms */

    /* Commit and release the lock */
    sqlite3_exec(db, "COMMIT;", 0, 0, 0);
    atomic_store(&g_writer_done, 1);

    sqlite3_close(db);
    return NULL;
}

static void *busy_reader(void *arg)
{
    (void)arg;
    sqlite3 *db;
    sqlite3_open(BUSY_DB_PATH, &db);

    /* Set a busy timeout so we don't spin forever */
    sqlite3_busy_timeout(db, 5000); /* 5 seconds max wait */

    /* Wait until writer has the lock */
    while (atomic_load(&g_writer_started) == 0)
        usleep(1000);

    /* Try to read — this will hit SQLITE_BUSY until writer commits */
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db, "SELECT count(*) FROM busy_test;", -1, &stmt, 0);
    if (rc == SQLITE_OK)
    {
        int step = sqlite3_step(stmt);
        if (step == SQLITE_BUSY)
        {
            atomic_store(&g_reader_busy_hit, 1);
            atomic_store(&g_reader_result, -1);
        }
        else if (step == SQLITE_ROW)
        {
            int64_t count = sqlite3_column_int64(stmt, 0);
            atomic_store(&g_reader_result, (int)count);
        }
        else
        {
            atomic_store(&g_reader_result, -2);
        }
        sqlite3_finalize(stmt);
    }
    else
    {
        atomic_store(&g_reader_result, -3);
    }

    sqlite3_close(db);
    return NULL;
}

static bool t_busy_writer_blocks_reader(void)
{
    cleanup_busy_db();

    /* Create the database and table first */
    sqlite3 *setup_db;
    sqlite3_open(BUSY_DB_PATH, &setup_db);
    sqlite3_exec(setup_db,
        "CREATE TABLE IF NOT EXISTS busy_test(id INTEGER PRIMARY KEY AUTOINCREMENT, value INTEGER);",
        0, 0, 0);
    sqlite3_close(setup_db);

    atomic_store(&g_writer_started, 0);
    atomic_store(&g_writer_done, 0);
    atomic_store(&g_reader_result, 0);
    atomic_store(&g_reader_busy_hit, 0);

    pthread_t tw, tr;
    pthread_create(&tw, NULL, busy_writer, NULL);
    pthread_create(&tr, NULL, busy_reader, NULL);
    pthread_join(tw, NULL);
    pthread_join(tr, NULL);

    int result = atomic_load(&g_reader_result);
    int busy = atomic_load(&g_reader_busy_hit);

    printf("         reader result=%d, busy_hit=%d\n", result, busy);

    /* Reader should have eventually succeeded (either during or after lock) */
    T_ASSERT(result >= 0, "reader eventually got a result");

    cleanup_busy_db();
    return true;
}

/* ============================================================
 *  TEST 2: OrmaDatabase concurrent write via run_multi_sql
 *
 *  Two OrmaDatabase connections to the same file, both writing.
 *  Tests that run_multi_sql handles SQLITE_BUSY correctly
 *  (or fails gracefully).
 * ============================================================ */

static atomic_int g_cw_success_a = 0;
static atomic_int g_cw_success_b = 0;
static atomic_int g_cw_errors_a  = 0;
static atomic_int g_cw_errors_b  = 0;

static void *concurrent_writer_a(void *arg)
{
    OrmaDatabase *o = (OrmaDatabase *)arg;
    for (int i = 0; i < 50; i++)
    {
        char sql[128];
        snprintf(sql, sizeof(sql),
            "INSERT INTO busy_test(value) VALUES(%d);", i);
        CSORMA_GENERIC_RESULT r = OrmaDatabase_run_multi_sql(o, (const uint8_t *)sql);
        if (r == CSORMA_GENERIC_RESULT_OK)
            atomic_fetch_add(&g_cw_success_a, 1);
        else
            atomic_fetch_add(&g_cw_errors_a, 1);
    }
    return NULL;
}

static void *concurrent_writer_b(void *arg)
{
    OrmaDatabase *o = (OrmaDatabase *)arg;
    for (int i = 100; i < 150; i++)
    {
        char sql[128];
        snprintf(sql, sizeof(sql),
            "INSERT INTO busy_test(value) VALUES(%d);", i);
        CSORMA_GENERIC_RESULT r = OrmaDatabase_run_multi_sql(o, (const uint8_t *)sql);
        if (r == CSORMA_GENERIC_RESULT_OK)
            atomic_fetch_add(&g_cw_success_b, 1);
        else
            atomic_fetch_add(&g_cw_errors_b, 1);
    }
    return NULL;
}

static bool t_busy_concurrent_orma_writers(void)
{
    cleanup_busy_db();

    OrmaDatabase *o1 = open_file_db();
    T_ASSERT_PTR_NOT_NULL(o1, "open db 1");
    setup_busy_table(o1);

    OrmaDatabase *o2 = open_file_db();
    T_ASSERT_PTR_NOT_NULL(o2, "open db 2");

    atomic_store(&g_cw_success_a, 0);
    atomic_store(&g_cw_success_b, 0);
    atomic_store(&g_cw_errors_a, 0);
    atomic_store(&g_cw_errors_b, 0);

    pthread_t ta, tb;
    pthread_create(&ta, NULL, concurrent_writer_a, o1);
    pthread_create(&tb, NULL, concurrent_writer_b, o2);
    pthread_join(ta, NULL);
    pthread_join(tb, NULL);

    int sa = atomic_load(&g_cw_success_a);
    int sb = atomic_load(&g_cw_success_b);
    int ea = atomic_load(&g_cw_errors_a);
    int eb = atomic_load(&g_cw_errors_b);

    printf("         writer A: %d success, %d errors\n", sa, ea);
    printf("         writer B: %d success, %d errors\n", sb, eb);

    /* At least some writes should succeed; SQLITE_BUSY errors
     * are expected without WAL mode or busy_timeout on the connections. */
    T_ASSERT(sa + sb > 0, "at least some writes succeeded");

    if (ea + eb > 0)
    {
        printf(C_YELLOW "         NOTE: %d SQLITE_BUSY errors occurred.\n" C_RESET, ea + eb);
        printf(C_YELLOW "         run_multi_sql uses sqlite3_exec which does not retry on BUSY.\n" C_RESET);
        printf(C_YELLOW "         Consider adding sqlite3_busy_timeout() after sqlite3_open().\n" C_RESET);
    }

    OrmaDatabase_shutdown(o1);
    OrmaDatabase_shutdown(o2);
    cleanup_busy_db();
    return true;
}

/* ============================================================
 *  TEST 3: WAL mode reduces SQLITE_BUSY
 *
 *  With WAL mode, readers don't block writers and writers
 *  don't block readers. This should reduce BUSY errors.
 * ============================================================ */

static bool t_busy_wal_reduces_contention(void)
{
    cleanup_busy_db();

    OrmaDatabase *o1 = open_file_db();
    T_ASSERT_PTR_NOT_NULL(o1, "open db 1");
    OrmaDatabase_set_wal_mode(o1, true);
    setup_busy_table(o1);

    OrmaDatabase *o2 = open_file_db();
    T_ASSERT_PTR_NOT_NULL(o2, "open db 2");
    OrmaDatabase_set_wal_mode(o2, true);

    atomic_store(&g_cw_success_a, 0);
    atomic_store(&g_cw_success_b, 0);
    atomic_store(&g_cw_errors_a, 0);
    atomic_store(&g_cw_errors_b, 0);

    pthread_t ta, tb;
    pthread_create(&ta, NULL, concurrent_writer_a, o1);
    pthread_create(&tb, NULL, concurrent_writer_b, o2);
    pthread_join(ta, NULL);
    pthread_join(tb, NULL);

    int sa = atomic_load(&g_cw_success_a);
    int sb = atomic_load(&g_cw_success_b);
    int ea = atomic_load(&g_cw_errors_a);
    int eb = atomic_load(&g_cw_errors_b);

    printf("         WAL mode writer A: %d success, %d errors\n", sa, ea);
    printf("         WAL mode writer B: %d success, %d errors\n", sb, eb);

    /* WAL should significantly reduce errors */
    T_ASSERT(sa + sb > 0, "writes succeed in WAL mode");

    if (ea + eb == 0)
        printf(C_GREEN "         WAL mode: zero BUSY errors!\n" C_RESET);
    else
        printf(C_YELLOW "         WAL mode: %d BUSY errors (still some contention)\n" C_RESET, ea + eb);

    OrmaDatabase_shutdown(o1);
    OrmaDatabase_shutdown(o2);
    cleanup_busy_db();
    return true;
}

/* ============================================================
 *  TEST 4: Read during long write transaction
 *
 *  Verifies that OrmaDatabase_run_sql_int64 can handle (or
 *  at least not crash on) SQLITE_BUSY.
 * ============================================================ */

static atomic_int g_long_writer_started = 0;

static void *long_writer(void *arg)
{
    (void)arg;
    sqlite3 *db;
    sqlite3_open(BUSY_DB_PATH, &db);

    sqlite3_exec(db, "BEGIN EXCLUSIVE;", 0, 0, 0);
    for (int i = 0; i < 100; i++)
    {
        char sql[128];
        snprintf(sql, sizeof(sql), "INSERT INTO busy_test(value) VALUES(%d);", i);
        sqlite3_exec(db, sql, 0, 0, 0);
        if (i == 0)
            atomic_store(&g_long_writer_started, 1);
    }
    /* Hold lock for a bit */
    usleep(100 * 1000);
    sqlite3_exec(db, "COMMIT;", 0, 0, 0);
    sqlite3_close(db);
    return NULL;
}

static bool t_busy_read_during_long_write(void)
{
    cleanup_busy_db();

    /* Setup DB */
    sqlite3 *setup;
    sqlite3_open(BUSY_DB_PATH, &setup);
    sqlite3_exec(setup,
        "CREATE TABLE IF NOT EXISTS busy_test(id INTEGER PRIMARY KEY AUTOINCREMENT, value INTEGER);",
        0, 0, 0);
    sqlite3_exec(setup, "INSERT INTO busy_test(value) VALUES(0);", 0, 0, 0);
    sqlite3_close(setup);

    atomic_store(&g_long_writer_started, 0);

    /* Start long writer in background */
    pthread_t tw;
    pthread_create(&tw, NULL, long_writer, NULL);

    /* Wait for writer to start */
    while (atomic_load(&g_long_writer_started) == 0)
        usleep(1000);

    /* Try to read via OrmaDatabase */
    OrmaDatabase *reader = open_file_db();
    T_ASSERT_PTR_NOT_NULL(reader, "open reader");

    long long t0 = now_ms();
    int64_t val = OrmaDatabase_run_sql_int64(reader,
        (const uint8_t *)"SELECT count(*) FROM busy_test;");
    long long elapsed = now_ms() - t0;

    printf("         read returned: %lld (took %lldms)\n", (long long)val, elapsed);

    /* The read might return the pre-transaction value (1) or
     * block until after commit. Either way, it shouldn't crash. */
    T_ASSERT(val >= 0, "read returned a valid value (no crash)");

    OrmaDatabase_shutdown(reader);
    pthread_join(tw, NULL);
    cleanup_busy_db();
    return true;
}

/* ============================================================
 *  TEST 5: Rapid open/close on same file
 *
 *  Multiple threads rapidly open and close connections to
 *  the same file. Tests file locking and cleanup.
 * ============================================================ */

static atomic_int g_oc_success = 0;
static atomic_int g_oc_errors  = 0;

static void *rapid_open_close_worker(void *arg)
{
    int tid = (int)(intptr_t)arg;
    (void)tid;

    for (int i = 0; i < 20; i++)
    {
        OrmaDatabase *o = open_file_db();
        if (o == NULL)
        {
            atomic_fetch_add(&g_oc_errors, 1);
            continue;
        }
        CSORMA_GENERIC_RESULT r = OrmaDatabase_run_multi_sql(o,
            (const uint8_t *)"CREATE TABLE IF NOT EXISTS busy_test(id INTEGER PRIMARY KEY, value INTEGER);");
        if (r == CSORMA_GENERIC_RESULT_OK)
            atomic_fetch_add(&g_oc_success, 1);
        else
            atomic_fetch_add(&g_oc_errors, 1);
        OrmaDatabase_shutdown(o);
    }
    return NULL;
}

static bool t_busy_rapid_open_close(void)
{
    cleanup_busy_db();

    atomic_store(&g_oc_success, 0);
    atomic_store(&g_oc_errors, 0);

    pthread_t threads[4];
    for (int i = 0; i < 4; i++)
        pthread_create(&threads[i], NULL, rapid_open_close_worker, (void *)(intptr_t)i);
    for (int i = 0; i < 4; i++)
        pthread_join(threads[i], NULL);

    int success = atomic_load(&g_oc_success);
    int errors  = atomic_load(&g_oc_errors);

    printf("         rapid open/close: %d success, %d errors\n", success, errors);
    T_ASSERT(success > 0, "at least some succeeded");

    if (errors > 0)
        printf(C_YELLOW "         NOTE: %d errors during rapid open/close (BUSY expected)\n" C_RESET, errors);

    cleanup_busy_db();
    return true;
}

/* ============================================================
 *  TEST 6: Verify no infinite spin on SQLITE_BUSY
 *
 *  If the csorma code has a SQLITE_BUSY spin loop with no
 *  timeout, this test will hang. We use fork() + waitpid()
 *  with a polling timeout to detect that.
 *
 *  The timeout must be significantly larger than the
 *  sqlite3_busy_timeout configured in csorma.c (3000ms) to
 *  avoid false positives on slow platforms (macOS arm, CI runners).
 *  SQLite's busy handler can take longer than the configured
 *  timeout due to platform lock timing and filesystem differences.
 * ============================================================ */

#include <sys/wait.h>

/* Timeout in seconds for the busy-spin detection.
 * Must be >> sqlite3_busy_timeout (3000ms) to avoid false positives.
 * On macOS arm CI, a 3000ms busy_timeout has been observed to take
 * up to 5700ms. We use 15s for generous headroom. */
#define BUSY_SPIN_TIMEOUT_SEC 15

static bool t_busy_no_infinite_spin(void)
{
    cleanup_busy_db();

    /* Setup DB */
    sqlite3 *setup;
    sqlite3_open(BUSY_DB_PATH, &setup);
    sqlite3_exec(setup,
        "CREATE TABLE IF NOT EXISTS busy_test(id INTEGER PRIMARY KEY, value INTEGER);"
        "INSERT INTO busy_test(value) VALUES(1);",
        0, 0, 0);

    /* Hold an exclusive lock */
    sqlite3_exec(setup, "BEGIN EXCLUSIVE;", 0, 0, 0);
    sqlite3_exec(setup, "INSERT INTO busy_test(value) VALUES(2);", 0, 0, 0);

    /*
     * Fork a child process that attempts the read.
     * If csorma has an infinite SQLITE_BUSY spin loop, the child
     * will hang forever. The parent polls with a timeout and
     * kills the child if it takes too long.
     */
    fflush(stdout);
    fflush(stderr);
    pid_t pid = fork();

    if (pid < 0)
    {
        /* fork failed — skip test */
        sqlite3_exec(setup, "COMMIT;", 0, 0, 0);
        sqlite3_close(setup);
        cleanup_busy_db();
        return true;
    }

    if (pid == 0)
    {
        /* ---- CHILD PROCESS ---- */
        freopen("/dev/null", "w", stdout);
        freopen("/dev/null", "w", stderr);

        OrmaDatabase *reader = open_file_db();
        if (reader == NULL)
            _exit(2);

        /* This call may spin forever if SQLITE_BUSY is not handled */
        int64_t val = OrmaDatabase_run_sql_int64(reader,
            (const uint8_t *)"SELECT count(*) FROM busy_test;");

        OrmaDatabase_shutdown(reader);
        _exit(val >= 0 ? 0 : 1);
    }

    /* ---- PARENT PROCESS ---- */
    long long t0 = now_ms();
    int status = 0;
    bool child_done = false;
    bool timed_out = false;

    while (1)
    {
        pid_t result = waitpid(pid, &status, WNOHANG);
        if (result == pid)
        {
            child_done = true;
            break;
        }

        long long elapsed_ms = now_ms() - t0;
        if (elapsed_ms > BUSY_SPIN_TIMEOUT_SEC * 1000LL)
        {
            timed_out = true;
            kill(pid, SIGKILL);
            waitpid(pid, &status, 0);
            break;
        }

        usleep(50 * 1000); /* 50ms poll interval */
    }

    long long elapsed = now_ms() - t0;

    /* Release the exclusive lock */
    sqlite3_exec(setup, "COMMIT;", 0, 0, 0);
    sqlite3_close(setup);

    if (timed_out)
    {
        printf(C_RED "\n");
        printf("  +-----------------------------------------------------------+\n");
        printf("  |  BUG: SQLITE_BUSY spin loop detected!                    |\n");
        printf("  +-----------------------------------------------------------+\n");
        printf("  |                                                           |\n");
        printf("  |  OrmaDatabase_run_sql_int64 did not return within        |\n");
        printf("  |  %d seconds while another connection held a lock.         |\n", BUSY_SPIN_TIMEOUT_SEC);
        printf("  |                                                           |\n");
        printf("  |  ROOT CAUSE: busy loop with no sleep and no timeout:     |\n");
        printf("  |    else if (step == SQLITE_BUSY) { continue; }           |\n");
        printf("  |                                                           |\n");
        printf("  |  FIX: add sqlite3_busy_timeout() after sqlite3_open(),   |\n");
        printf("  |  or add usleep() in the BUSY branch, or add a retry      |\n");
        printf("  |  counter with a maximum.                                  |\n");
        printf("  +-----------------------------------------------------------+\n");
        printf(C_RESET "\n");

        cleanup_busy_db();
        _tf_failed++;
        return false;
    }

    printf("         child completed in %lldms (no infinite spin)\n", elapsed);

    if (child_done && WIFEXITED(status))
    {
        int exit_code = WEXITSTATUS(status);
        printf("         child exit code: %d\n", exit_code);
    }

    cleanup_busy_db();
    return true;
}

/* ============================================================
 *  MAIN
 * ============================================================ */
int main(void)
{
    printf(C_BOLD "\n");
    printf("  ================================================================\n");
    printf("   CSORMA SQLITE_BUSY HANDLING TESTS\n");
    printf("   Source: ../template/csorma.c (compiled directly)\n");
    printf("   NOTE: Uses file-based databases in /tmp/\n");
    printf("  ================================================================\n");
    printf(C_RESET "\n");

    TEST_SUITE("Writer blocks reader");
    RUN_TEST(t_busy_writer_blocks_reader);
    SUITE_END();

    TEST_SUITE("Concurrent OrmaDatabase writers");
    RUN_TEST(t_busy_concurrent_orma_writers);
    SUITE_END();

    TEST_SUITE("WAL mode reduces contention");
    RUN_TEST(t_busy_wal_reduces_contention);
    SUITE_END();

    TEST_SUITE("Read during long write");
    RUN_TEST(t_busy_read_during_long_write);
    SUITE_END();

    TEST_SUITE("Rapid open/close same file");
    RUN_TEST(t_busy_rapid_open_close);
    SUITE_END();

    TEST_SUITE("SQLITE_BUSY infinite spin detection");
    RUN_TEST(t_busy_no_infinite_spin);
    SUITE_END();

    return test_summary("SQLITE_BUSY Handling");
}

