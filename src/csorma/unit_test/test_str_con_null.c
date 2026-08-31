/*
 * test_str_con_null.c — Tests for csorma_str_con with NULL b1
 *
 * csorma_str_con does:
 *
 *   memcpy(out->cur, b1, b1_len);
 *
 * If b1 is NULL:
 *   - b1_len == 0: memcpy(dst, NULL, 0) — technically UB per C standard,
 *     but works on most implementations
 *   - b1_len > 0:  memcpy(dst, NULL, n) — definite UB, will crash
 *
 * Since these cases crash, we use fork() to detect the crash safely
 * without killing the test suite (same technique as test_logger.c).
 */

#include "test_framework.h"
#include "csorma.h"

#include <unistd.h>
#include <sys/wait.h>

/* ============================================================
 *  Helper: run a dangerous function in a forked child process
 * ============================================================ */

static bool _run_in_child(void (*fn)(void))
{
    fflush(stdout);
    fflush(stderr);
    pid_t pid = fork();
    if (pid < 0)
        return true; /* fork failed, skip */

    if (pid == 0)
    {
        /* Child: run the dangerous function */
        freopen("/dev/null", "w", stderr);
        fn();
        _exit(0);
    }

    /* Parent: wait for child */
    int status;
    waitpid(pid, &status, 0);
    if (WIFEXITED(status) && WEXITSTATUS(status) == 0)
        return true;  /* child survived */
    return false;     /* child crashed */
}

/* ============================================================
 *  TEST 1: csorma_str_con(s, NULL, 0) — zero-length NULL
 *
 *  memcpy(dst, NULL, 0) is technically undefined behavior per
 *  the C standard, but works on virtually all implementations
 *  because no bytes are actually copied.
 * ============================================================ */

static void _con_null_zero_fn(void)
{
    csorma_s *s = csorma_str2_build("hello");
    s = csorma_str_con(s, NULL, 0);
    csorma_str_free(s);
}

static bool t_con_null_zero_len(void)
{
    bool survived = _run_in_child(_con_null_zero_fn);

    if (!survived)
    {
        printf(C_RED "\n");
        printf("  +-----------------------------------------------------------+\n");
        printf("  |  BUG: csorma_str_con(s, NULL, 0) crashes                  |\n");
        printf("  +-----------------------------------------------------------+\n");
        printf("  |                                                           |\n");
        printf("  |  memcpy(dst, NULL, 0) is undefined behavior per the       |\n");
        printf("  |  C standard, even though no bytes are copied.             |\n");
        printf("  |                                                           |\n");
        printf("  |  FIX: add a guard at the top of csorma_str_con:           |\n");
        printf("  |    if (b1 == NULL || b1_len == 0) return out;             |\n");
        printf("  +-----------------------------------------------------------+\n");
        printf(C_RESET "\n");
        _tf_failed++;
        return false;
    }

    printf("         csorma_str_con(s, NULL, 0) survived\n");
    return true;
}

/* ============================================================
 *  TEST 2: csorma_str_con(s, NULL, 5) — non-zero length NULL
 *
 *  memcpy(dst, NULL, 5) is definite undefined behavior and
 *  will crash or read garbage memory.
 * ============================================================ */

static void _con_null_nonzero_fn(void)
{
    csorma_s *s = csorma_str2_build("hello");
    s = csorma_str_con(s, NULL, 5);
    csorma_str_free(s);
}

static bool t_con_null_nonzero_len(void)
{
    bool survived = _run_in_child(_con_null_nonzero_fn);

    if (!survived)
    {
        printf(C_RED "\n");
        printf("  +-----------------------------------------------------------+\n");
        printf("  |  BUG: csorma_str_con(s, NULL, 5) crashes                  |\n");
        printf("  +-----------------------------------------------------------+\n");
        printf("  |                                                           |\n");
        printf("  |  memcpy(dst, NULL, 5) reads from address NULL.            |\n");
        printf("  |  This is a guaranteed segfault on all platforms.          |\n");
        printf("  |                                                           |\n");
        printf("  |  FIX: add a NULL guard at the top of csorma_str_con:      |\n");
        printf("  |    if (b1 == NULL) return out;                            |\n");
        printf("  +-----------------------------------------------------------+\n");
        printf(C_RESET "\n");
        _tf_failed++;
        return false;
    }

    printf("         csorma_str_con(s, NULL, 5) survived\n");
    return true;
}

/* ============================================================
 *  TEST 3: csorma_str_con(NULL, NULL, 0) — both NULL
 * ============================================================ */

static void _con_both_null_fn(void)
{
    csorma_s *s = NULL;
    s = csorma_str_con(s, NULL, 0);
    if (s != NULL)
        csorma_str_free(s);
}

static bool t_con_both_null(void)
{
    bool survived = _run_in_child(_con_both_null_fn);

    if (!survived)
    {
        printf("         csorma_str_con(NULL, NULL, 0) crashed\n");
        _tf_failed++;
        return false;
    }

    printf("         csorma_str_con(NULL, NULL, 0) survived\n");
    return true;
}

/* ============================================================
 *  TEST 4: csorma_str_con(NULL, NULL, 5) — NULL base, NULL data
 * ============================================================ */

static void _con_null_base_null_data_fn(void)
{
    csorma_s *s = NULL;
    s = csorma_str_con(s, NULL, 5);
    if (s != NULL)
        csorma_str_free(s);
}

static bool t_con_null_base_null_data(void)
{
    bool survived = _run_in_child(_con_null_base_null_data_fn);

    if (!survived)
    {
        printf("         csorma_str_con(NULL, NULL, 5) crashed\n");
        _tf_failed++;
        return false;
    }

    printf("         csorma_str_con(NULL, NULL, 5) survived\n");
    return true;
}

/* ============================================================
 *  TEST 5: csorma_str_build(NULL, 5) — same issue in str_build
 * ============================================================ */

static void _build_null_fn(void)
{
    csorma_s *s = csorma_str_build(NULL, 5);
    if (s != NULL)
        csorma_str_free(s);
}

static bool t_build_null_nonzero(void)
{
    bool survived = _run_in_child(_build_null_fn);

    if (!survived)
    {
        printf(C_RED "\n");
        printf("  +-----------------------------------------------------------+\n");
        printf("  |  BUG: csorma_str_build(NULL, 5) crashes                   |\n");
        printf("  +-----------------------------------------------------------+\n");
        printf("  |                                                           |\n");
        printf("  |  memcpy(out->s, NULL, 5) reads from address NULL.         |\n");
        printf("  |                                                           |\n");
        printf("  |  FIX: add a NULL guard at the top of csorma_str_build:    |\n");
        printf("  |    if (b1 == NULL) return NULL;                           |\n");
        printf("  +-----------------------------------------------------------+\n");
        printf(C_RESET "\n");
        _tf_failed++;
        return false;
    }

    printf("         csorma_str_build(NULL, 5) survived\n");
    return true;
}

/* ============================================================
 *  TEST 6: csorma_str_build(NULL, 0) — zero-length NULL
 * ============================================================ */

static void _build_null_zero_fn(void)
{
    csorma_s *s = csorma_str_build(NULL, 0);
    if (s != NULL)
        csorma_str_free(s);
}

static bool t_build_null_zero(void)
{
    bool survived = _run_in_child(_build_null_zero_fn);

    if (!survived)
    {
        printf("         csorma_str_build(NULL, 0) crashed\n");
        _tf_failed++;
        return false;
    }

    printf("         csorma_str_build(NULL, 0) survived\n");
    return true;
}

/* ============================================================
 *  TEST 7: csorma_str_con2 with NULL append (already handled)
 *
 *  csorma_str_con2 checks for NULL append and returns out
 *  unchanged. Verify this works.
 * ============================================================ */

static bool t_con2_null_append_safe(void)
{
    csorma_s *s = csorma_str2_build("hello");
    s = csorma_str_con2(s, NULL);
    T_ASSERT_INT_EQ(s->l, 5, "unchanged after NULL append");
    T_ASSERT_MEM_EQ(s->s, "hello", 5, "content intact");
    csorma_str_free(s);
    return true;
}

/* ============================================================
 *  TEST 8: csorma_str_con with valid pointer but wrong length
 *
 *  Passing a length larger than the actual string reads past
 *  the end of the source buffer. This is a caller error but
 *  we document the behavior.
 * ============================================================ */

static void _con_overlength_fn(void)
{
    csorma_s *s = csorma_str2_build("hello");
    /* "hi" is only 2 bytes, but we claim 100 — reads past buffer */
    s = csorma_str_con(s, "hi", 100);
    csorma_str_free(s);
}

static bool t_con_overlength_read(void)
{
    bool survived = _run_in_child(_con_overlength_fn);

    if (!survived)
    {
        printf("         overlength read crashed (expected with ASAN)\n");
    }
    else
    {
        printf("         overlength read survived (no ASAN, or lucky)\n");
    }
    /* This is a caller error, not a library bug — pass either way */
    return true;
}

/* ============================================================
 *  MAIN
 * ============================================================ */
int main(void)
{
    printf(C_BOLD "\n");
    printf("  ================================================================\n");
    printf("   CSORMA csorma_str_con NULL b1 TESTS\n");
    printf("   Source: ../template/csorma.c (compiled directly)\n");
    printf("   NOTE: Uses fork() to detect crashes safely\n");
    printf("  ================================================================\n");
    printf(C_RESET "\n");

    TEST_SUITE("csorma_str_con with NULL b1");
    RUN_TEST(t_con_null_zero_len);
    RUN_TEST(t_con_null_nonzero_len);
    RUN_TEST(t_con_both_null);
    RUN_TEST(t_con_null_base_null_data);
    SUITE_END();

    TEST_SUITE("csorma_str_build with NULL b1");
    RUN_TEST(t_build_null_nonzero);
    RUN_TEST(t_build_null_zero);
    SUITE_END();

    TEST_SUITE("Safe NULL handling (already guarded)");
    RUN_TEST(t_con2_null_append_safe);
    SUITE_END();

    TEST_SUITE("Caller error documentation");
    RUN_TEST(t_con_overlength_read);
    SUITE_END();

    return test_summary("csorma_str_con NULL b1");
}

