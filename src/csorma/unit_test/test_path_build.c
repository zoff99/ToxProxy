/*
 * test_path_build.c — Tests for database path construction
 *
 * str_buf_concat is a static function inside csorma.c used by
 * OrmaDatabase_init to build the full database file path from
 * directory + filename. Since it's static, we test it indirectly
 * through OrmaDatabase_init with various path combinations.
 *
 * This tests the REAL code path that users will hit.
 */

#include "test_framework.h"
#include "csorma.h"

#include <unistd.h>
#include <sys/stat.h>

/* ============================================================
 *  Helpers
 * ============================================================ */

static void cleanup_file(const char *path)
{
    remove(path);
    /* Also remove SQLite auxiliary files */
    char aux[512];
    snprintf(aux, sizeof(aux), "%s-journal", path);
    remove(aux);
    snprintf(aux, sizeof(aux), "%s-wal", path);
    remove(aux);
    snprintf(aux, sizeof(aux), "%s-shm", path);
    remove(aux);
}

static bool file_exists(const char *path)
{
    struct stat st;
    return (stat(path, &st) == 0);
}

/* ============================================================
 *  TEST 1: Basic directory + filename
 * ============================================================ */

static bool t_path_basic(void)
{
    const char *dir = "/tmp/";
    const char *name = "_csorma_path_test_1.db";
    char fullpath[256];
    snprintf(fullpath, sizeof(fullpath), "%s%s", dir, name);
    cleanup_file(fullpath);

    OrmaDatabase *o = OrmaDatabase_init(
        (const uint8_t *)dir, (uint32_t)strlen(dir),
        (const uint8_t *)name, (uint32_t)strlen(name));

    T_ASSERT_PTR_NOT_NULL(o, "db opened");

    /* Verify the file was created at the expected path */
    T_ASSERT(file_exists(fullpath), "file created at dir+name");

    OrmaDatabase_shutdown(o);
    cleanup_file(fullpath);
    return true;
}

/* ============================================================
 *  TEST 2: Directory without trailing slash
 *
 *  IMPORTANT BEHAVIOR: str_buf_concat does NOT add a separator.
 *  dir="/tmp" + name="test.db" → "/tmptest.db" (no slash).
 *
 *  This means the caller MUST include a trailing slash in the
 *  directory, or the resulting path will be wrong.
 *
 *  Here we use a path that lands at the filesystem root, which
 *  a non-root user cannot write to. OrmaDatabase_init correctly
 *  returns NULL. This proves the concatenation happened without
 *  a separator.
 * ============================================================ */

static bool t_path_no_trailing_slash(void)
{
    const char *dir = "/tmp";   /* no trailing slash */
    const char *name = "_csorma_path_test_2.db";

    /* Expected concatenated path: "/tmp_csorma_path_test_2.db"
     * This is at the filesystem root — NOT inside /tmp/ */
    char fullpath[256];
    snprintf(fullpath, sizeof(fullpath), "%s%s", dir, name);
    printf("         dir='/tmp' + name → '%s'\n", fullpath);
    printf("         (note: this is at filesystem root, NOT inside /tmp/)\n");

    OrmaDatabase *o = OrmaDatabase_init(
        (const uint8_t *)dir, (uint32_t)strlen(dir),
        (const uint8_t *)name, (uint32_t)strlen(name));

    if (getuid() == 0)
    {
        /* Running as root: the file CAN be created at / */
        T_ASSERT_PTR_NOT_NULL(o, "root can create file at /");
        if (o) OrmaDatabase_shutdown(o);
        cleanup_file(fullpath);
    }
    else
    {
        /* Non-root: cannot write to /, so init must fail gracefully */
        T_ASSERT_PTR_NULL(o, "non-root cannot create file at / (expected failure)");
        printf("         OrmaDatabase_init returned NULL — correct for non-root\n");
        printf("         CONFIRMED: str_buf_concat adds NO path separator\n");
    }

    return true;
}

/* ============================================================
 *  TEST 3: Empty directory (relative path)
 * ============================================================ */

static bool t_path_empty_dir(void)
{
    const char *dir = "";
    const char *name = "_csorma_path_test_3.db";
    cleanup_file(name);

    OrmaDatabase *o = OrmaDatabase_init(
        (const uint8_t *)dir, (uint32_t)strlen(dir),
        (const uint8_t *)name, (uint32_t)strlen(name));

    T_ASSERT_PTR_NOT_NULL(o, "db opened with empty dir");
    T_ASSERT(file_exists(name), "file created in current dir");

    OrmaDatabase_shutdown(o);
    cleanup_file(name);
    return true;
}

/* ============================================================
 *  TEST 4: :memory: database (no file created)
 * ============================================================ */

static bool t_path_memory(void)
{
    OrmaDatabase *o = OrmaDatabase_init(
        (const uint8_t *)":memory:", 8,
        (const uint8_t *)"", 0);

    T_ASSERT_PTR_NOT_NULL(o, ":memory: db opened");

    /* Verify it works */
    CSORMA_GENERIC_RESULT r = OrmaDatabase_run_multi_sql(o,
        (const uint8_t *)"CREATE TABLE t(x INT); INSERT INTO t VALUES(42);");
    T_ASSERT_INT_EQ(r, CSORMA_GENERIC_RESULT_OK, "memory db works");

    int64_t v = OrmaDatabase_run_sql_int64(o,
        (const uint8_t *)"SELECT x FROM t;");
    T_ASSERT_INT_EQ(v, 42, "read from memory db");

    OrmaDatabase_shutdown(o);
    return true;
}

/* ============================================================
 *  TEST 5: :memory: with non-empty filename
 *
 *  DOCUMENTED FOOTGUN: str_buf_concat produces ":memory:ignored.db".
 *  SQLite only treats the path as in-memory when it is EXACTLY
 *  ":memory:". Any other string becomes a regular filename, so a
 *  file literally named ":memory:ignored.db" gets created.
 * ============================================================ */

static bool t_path_memory_with_name(void)
{
    const char *weird_file = ":memory:ignored.db";
    cleanup_file(weird_file);

    OrmaDatabase *o = OrmaDatabase_init(
        (const uint8_t *)":memory:", 8,
        (const uint8_t *)"ignored.db", 10);

    T_ASSERT_PTR_NOT_NULL(o, "db opened");

    /* Verify: a FILE was created, not an in-memory db */
    bool file_created = file_exists(weird_file);
    printf("         ':memory:' + 'ignored.db' -> file '%s' created: %s\n",
           weird_file, file_created ? "YES" : "no");
    T_ASSERT(file_created, "SQLite created a file (not in-memory)");

    OrmaDatabase_shutdown(o);
    cleanup_file(weird_file);

    /* Verify cleanup */
    T_ASSERT(!file_exists(weird_file), "file cleaned up");
    return true;
}

/* ============================================================
 *  TEST 6: Subdirectory path
 * ============================================================ */

static bool t_path_subdirectory(void)
{
    /* Create a subdirectory */
    const char *subdir = "/tmp/_csorma_path_test_subdir/";
    mkdir(subdir, 0755);

    const char *name = "test.db";
    char fullpath[256];
    snprintf(fullpath, sizeof(fullpath), "%s%s", subdir, name);
    cleanup_file(fullpath);

    OrmaDatabase *o = OrmaDatabase_init(
        (const uint8_t *)subdir, (uint32_t)strlen(subdir),
        (const uint8_t *)name, (uint32_t)strlen(name));

    T_ASSERT_PTR_NOT_NULL(o, "db in subdirectory");
    T_ASSERT(file_exists(fullpath), "file in subdirectory");

    OrmaDatabase_shutdown(o);
    cleanup_file(fullpath);
    rmdir(subdir);
    return true;
}

/* ============================================================
 *  TEST 7: Path with spaces
 * ============================================================ */

static bool t_path_with_spaces(void)
{
    const char *dir = "/tmp/_csorma path test/";
    mkdir(dir, 0755);

    const char *name = "my database.db";
    char fullpath[256];
    snprintf(fullpath, sizeof(fullpath), "%s%s", dir, name);
    cleanup_file(fullpath);

    OrmaDatabase *o = OrmaDatabase_init(
        (const uint8_t *)dir, (uint32_t)strlen(dir),
        (const uint8_t *)name, (uint32_t)strlen(name));

    T_ASSERT_PTR_NOT_NULL(o, "db with spaces in path");
    T_ASSERT(file_exists(fullpath), "file with spaces created");

    OrmaDatabase_shutdown(o);
    cleanup_file(fullpath);
    rmdir(dir);
    return true;
}

/* ============================================================
 *  TEST 8: Nonexistent directory (should fail gracefully)
 * ============================================================ */

static bool t_path_nonexistent_dir(void)
{
    const char *dir = "/tmp/_csorma_nonexistent_dir_xyz/";
    const char *name = "test.db";

    OrmaDatabase *o = OrmaDatabase_init(
        (const uint8_t *)dir, (uint32_t)strlen(dir),
        (const uint8_t *)name, (uint32_t)strlen(name));

    /* SQLite cannot create the file in a nonexistent directory.
     * OrmaDatabase_init should return NULL or handle the error. */
    if (o == NULL)
    {
        printf("         nonexistent dir → NULL returned (correct)\n");
    }
    else
    {
        printf("         nonexistent dir → db handle returned (unexpected)\n");
        OrmaDatabase_shutdown(o);
    }
    /* Either way, no crash */
    return true;
}

/* ============================================================
 *  TEST 9: Very long filename
 * ============================================================ */

static bool t_path_long_filename(void)
{
    /* 200-char filename (within typical 255 limit) */
    char name[256];
    memset(name, 'x', 200);
    memcpy(name + 197, ".db", 3);
    name[200] = '\0';

    const char *dir = "/tmp/";
    char fullpath[512];
    snprintf(fullpath, sizeof(fullpath), "%s%s", dir, name);
    cleanup_file(fullpath);

    OrmaDatabase *o = OrmaDatabase_init(
        (const uint8_t *)dir, (uint32_t)strlen(dir),
        (const uint8_t *)name, (uint32_t)strlen(name));

    T_ASSERT_PTR_NOT_NULL(o, "long filename db opened");
    T_ASSERT(file_exists(fullpath), "long filename file created");

    OrmaDatabase_shutdown(o);
    cleanup_file(fullpath);
    return true;
}

/* ============================================================
 *  TEST 10: Relative path (no leading slash)
 * ============================================================ */

static bool t_path_relative(void)
{
    const char *dir = "./";
    const char *name = "_csorma_path_test_rel.db";
    cleanup_file(name);

    OrmaDatabase *o = OrmaDatabase_init(
        (const uint8_t *)dir, (uint32_t)strlen(dir),
        (const uint8_t *)name, (uint32_t)strlen(name));

    T_ASSERT_PTR_NOT_NULL(o, "relative path db opened");
    T_ASSERT(file_exists(name), "file in current dir");

    OrmaDatabase_shutdown(o);
    cleanup_file(name);
    return true;
}

/* ============================================================
 *  TEST 11: Open, write, close, reopen same path
 *
 *  Verifies the path is constructed consistently across
 *  multiple init/shutdown cycles.
 * ============================================================ */

static bool t_path_reopen(void)
{
    const char *dir = "/tmp/";
    const char *name = "_csorma_path_test_reopen.db";
    char fullpath[256];
    snprintf(fullpath, sizeof(fullpath), "%s%s", dir, name);
    cleanup_file(fullpath);

    /* First open: create and write */
    OrmaDatabase *o1 = OrmaDatabase_init(
        (const uint8_t *)dir, (uint32_t)strlen(dir),
        (const uint8_t *)name, (uint32_t)strlen(name));
    T_ASSERT_PTR_NOT_NULL(o1, "first open");
    OrmaDatabase_run_multi_sql(o1,
        (const uint8_t *)"CREATE TABLE t(x INT); INSERT INTO t VALUES(123);");
    OrmaDatabase_shutdown(o1);

    /* Second open: read back */
    OrmaDatabase *o2 = OrmaDatabase_init(
        (const uint8_t *)dir, (uint32_t)strlen(dir),
        (const uint8_t *)name, (uint32_t)strlen(name));
    T_ASSERT_PTR_NOT_NULL(o2, "second open");
    int64_t v = OrmaDatabase_run_sql_int64(o2,
        (const uint8_t *)"SELECT x FROM t;");
    T_ASSERT_INT_EQ(v, 123, "data persisted across reopen");
    OrmaDatabase_shutdown(o2);

    cleanup_file(fullpath);
    return true;
}

/* ============================================================
 *  TEST 12: Empty filename (directory only)
 * ============================================================ */

static bool t_path_empty_filename(void)
{
    const char *dir = "/tmp/";
    const char *name = "";

    /* dir="/tmp/" + name="" → path="/tmp/"
     * SQLite will try to open "/tmp/" as a database, which should fail */
    OrmaDatabase *o = OrmaDatabase_init(
        (const uint8_t *)dir, (uint32_t)strlen(dir),
        (const uint8_t *)name, (uint32_t)strlen(name));

    if (o == NULL)
    {
        printf("         empty filename → NULL (cannot open directory as db)\n");
    }
    else
    {
        printf("         empty filename → handle returned\n");
        OrmaDatabase_shutdown(o);
    }
    /* No crash is the test */
    return true;
}

/* ============================================================
 *  MAIN
 * ============================================================ */
int main(void)
{
    printf(C_BOLD "\n");
    printf("  ================================================================\n");
    printf("   CSORMA PATH BUILDING TESTS (via OrmaDatabase_init)\n");
    printf("   Source: ../template/csorma.c (compiled directly)\n");
    printf("   NOTE: str_buf_concat is static, tested indirectly\n");
    printf("  ================================================================\n");
    printf(C_RESET "\n");

    TEST_SUITE("Basic path construction");
    RUN_TEST(t_path_basic);
    RUN_TEST(t_path_no_trailing_slash);
    RUN_TEST(t_path_empty_dir);
    SUITE_END();

    TEST_SUITE(":memory: database");
    RUN_TEST(t_path_memory);
    RUN_TEST(t_path_memory_with_name);
    SUITE_END();

    TEST_SUITE("Special paths");
    RUN_TEST(t_path_subdirectory);
    RUN_TEST(t_path_with_spaces);
    RUN_TEST(t_path_relative);
    SUITE_END();

    TEST_SUITE("Edge cases");
    RUN_TEST(t_path_nonexistent_dir);
    RUN_TEST(t_path_long_filename);
    RUN_TEST(t_path_empty_filename);
    SUITE_END();

    TEST_SUITE("Path consistency");
    RUN_TEST(t_path_reopen);
    SUITE_END();

    return test_summary("Path Building");
}

