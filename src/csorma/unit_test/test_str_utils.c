/*
 * test_str_utils.c — Tests for csorma_str* functions
 * Links against the REAL ../template/csorma.c (compiled by Makefile)
 */
#include "test_framework.h"
#include "csorma.h"

/* ============================================================
 *  csorma_str2_build() tests
 * ============================================================ */
static bool t_build_basic(void) {
    csorma_s *s = csorma_str2_build("hello");
    T_ASSERT_PTR_NOT_NULL(s, "non-NULL");
    T_ASSERT_INT_EQ(s->l, 5, "len");
    T_ASSERT_MEM_EQ(s->s, "hello", 5, "content");
    T_ASSERT(s->s[5] == '\0', "NUL terminated");
    T_ASSERT_PTR_EQ(s->cur, s->s + 5, "cur = s+l");
    T_ASSERT_INT_EQ(s->n, 1, "n flag");
    csorma_str_free(s);
    return true;
}

static bool t_build_empty(void) {
    csorma_s *s = csorma_str2_build("");
    T_ASSERT_PTR_NOT_NULL(s, "non-NULL for empty");
    T_ASSERT_INT_EQ(s->l, 0, "len=0");
    T_ASSERT(s->s[0] == '\0', "NUL at [0]");
    T_ASSERT_PTR_EQ(s->cur, s->s, "cur = s");
    csorma_str_free(s);
    return true;
}

static bool t_build_null(void) {
    csorma_s *s = csorma_str2_build(NULL);
    T_ASSERT_PTR_NULL(s, "NULL input returns NULL");
    return true;
}

static bool t_build_single_char(void) {
    csorma_s *s = csorma_str2_build("X");
    T_ASSERT_INT_EQ(s->l, 1, "len=1");
    T_ASSERT(s->s[0] == 'X', "content");
    T_ASSERT(s->s[1] == '\0', "NUL");
    csorma_str_free(s);
    return true;
}

static bool t_build_long(void) {
    char buf[10000];
    memset(buf, 'A', 9999);
    buf[9999] = '\0';
    csorma_s *s = csorma_str2_build(buf);
    T_ASSERT_PTR_NOT_NULL(s, "non-NULL");
    T_ASSERT_INT_EQ(s->l, 9999, "len=9999");
    T_ASSERT(s->s[9998] == 'A', "last char");
    T_ASSERT(s->s[9999] == '\0', "NUL at end");
    csorma_str_free(s);
    return true;
}

/* ============================================================
 *  csorma_str_build() tests
 * ============================================================ */
static bool t_build_len_basic(void) {
    csorma_s *s = csorma_str_build("hello", 5);
    T_ASSERT_PTR_NOT_NULL(s, "non-NULL");
    T_ASSERT_INT_EQ(s->l, 5, "len");
    T_ASSERT_MEM_EQ(s->s, "hello", 5, "content");
    T_ASSERT(s->s[5] == '\0', "NUL");
    csorma_str_free(s);
    return true;
}

static bool t_build_len_zero(void) {
    csorma_s *s = csorma_str_build("hello", 0);
    T_ASSERT_INT_EQ(s->l, 0, "len=0");
    T_ASSERT(s->s[0] == '\0', "empty NUL");
    csorma_str_free(s);
    return true;
}

static bool t_build_len_partial(void) {
    csorma_s *s = csorma_str_build("hello world", 5);
    T_ASSERT_INT_EQ(s->l, 5, "len=5");
    T_ASSERT_MEM_EQ(s->s, "hello", 5, "only first 5");
    csorma_str_free(s);
    return true;
}

static bool t_build_len_binary(void) {
    const char d[] = {'A', '\0', 'B', '\0', 'C'};
    csorma_s *s = csorma_str_build(d, 5);
    T_ASSERT_INT_EQ(s->l, 5, "len=5");
    T_ASSERT(s->s[0] == 'A', "byte 0");
    T_ASSERT(s->s[1] == '\0', "byte 1 NUL");
    T_ASSERT(s->s[2] == 'B', "byte 2");
    T_ASSERT(s->s[3] == '\0', "byte 3 NUL");
    T_ASSERT(s->s[4] == 'C', "byte 4");
    csorma_str_free(s);
    return true;
}

static bool t_build_len_256(void) {
    uint8_t buf[256];
    for (int i = 0; i < 256; i++) buf[i] = (uint8_t)i;
    csorma_s *s = csorma_str_build((const char*)buf, 256);
    T_ASSERT_INT_EQ(s->l, 256, "len=256");
    for (int i = 0; i < 256; i++) {
        if (s->s[i] != (uint8_t)i) {
            printf("         Byte mismatch at %d\n", i);
            _tf_failed++;
            csorma_str_free(s);
            return false;
        }
    }
    csorma_str_free(s);
    return true;
}

/* ============================================================
 *  csorma_str_con() tests
 * ============================================================ */
static bool t_con_basic(void) {
    csorma_s *s = csorma_str2_build("hello");
    s = csorma_str_con(s, " world", 6);
    T_ASSERT_INT_EQ(s->l, 11, "len=11");
    T_ASSERT_MEM_EQ(s->s, "hello world", 11, "content");
    T_ASSERT(s->s[11] == '\0', "NUL");
    csorma_str_free(s);
    return true;
}

static bool t_con_null(void) {
    csorma_s *s = csorma_str_con(NULL, "fresh", 5);
    T_ASSERT_PTR_NOT_NULL(s, "creates from NULL");
    T_ASSERT_INT_EQ(s->l, 5, "len=5");
    T_ASSERT_MEM_EQ(s->s, "fresh", 5, "content");
    csorma_str_free(s);
    return true;
}

static bool t_con_empty_append(void) {
    csorma_s *s = csorma_str2_build("hello");
    s = csorma_str_con(s, "", 0);
    T_ASSERT_INT_EQ(s->l, 5, "len unchanged");
    T_ASSERT_MEM_EQ(s->s, "hello", 5, "content unchanged");
    csorma_str_free(s);
    return true;
}

static bool t_con_to_empty(void) {
    csorma_s *s = csorma_str2_build("");
    s = csorma_str_con(s, "hello", 5);
    T_ASSERT_INT_EQ(s->l, 5, "len=5");
    T_ASSERT_MEM_EQ(s->s, "hello", 5, "content");
    csorma_str_free(s);
    return true;
}

static bool t_con_sequential(void) {
    csorma_s *s = csorma_str2_build("");
    s = csorma_str_con(s, "a", 1);
    s = csorma_str_con(s, "b", 1);
    s = csorma_str_con(s, "c", 1);
    s = csorma_str_con(s, "d", 1);
    s = csorma_str_con(s, "e", 1);
    T_ASSERT_INT_EQ(s->l, 5, "len=5");
    T_ASSERT_MEM_EQ(s->s, "abcde", 5, "content");
    csorma_str_free(s);
    return true;
}

static bool t_con_many_small(void) {
    csorma_s *s = csorma_str2_build("");
    for (int i = 0; i < 5000; i++)
        s = csorma_str_con(s, ".", 1);
    T_ASSERT_INT_EQ(s->l, 5000, "len=5000");
    bool ok = true;
    for (uint32_t i = 0; i < s->l; i++)
        if (s->s[i] != '.') { ok = false; break; }
    T_ASSERT(ok, "all dots");
    csorma_str_free(s);
    return true;
}

static bool t_con_binary(void) {
    const char bin[] = {'\x00', '\x01', '\xFF', '\xFE', '\x7F'};
    csorma_s *s = csorma_str2_build("");
    s = csorma_str_con(s, bin, 5);
    T_ASSERT_INT_EQ(s->l, 5, "len=5");
    T_ASSERT_MEM_EQ(s->s, bin, 5, "binary preserved");
    csorma_str_free(s);
    return true;
}

static bool t_con_large(void) {
    csorma_s *s = csorma_str2_build("");
    uint32_t sz = 100000;
    char *big = calloc(1, sz);
    memset(big, 'Z', sz);
    s = csorma_str_con(s, big, sz);
    T_ASSERT_INT_EQ(s->l, sz, "len=100K");
    T_ASSERT(s->s[0] == 'Z' && s->s[sz-1] == 'Z', "first/last");
    free(big);
    csorma_str_free(s);
    return true;
}

/* ============================================================
 *  THE POINTER BUG TESTS
 * ============================================================ */
static bool t_con_cur_pointer(void) {
    csorma_s *s = csorma_str2_build("hello");
    s = csorma_str_con(s, " world", 6);
    uint8_t *correct = s->s + s->l;

    if (s->cur != correct) {
        printf(C_RED "\n");
        printf("  +-----------------------------------------------------------+\n");
        printf("  |          POINTER BUG DETECTED IN csorma_str_con()         |\n");
        printf("  +-----------------------------------------------------------+\n");
        printf("  |                                                           |\n");
        printf("  |  Buffer: [h][e][l][l][o][ ][w][o][r][l][d][\\0]           |\n");
        printf("  |          [0][1][2][3][4][5][6][7][8][9][10][11] 12 bytes  |\n");
        printf("  |                                                           |\n");
        printf("  |  CORRECT cur = s + %-2u = %p                 |\n", s->l, (void*)correct);
        printf("  |  ACTUAL  cur =          %p                 |\n", (void*)s->cur);
        printf("  |  OVERFLOW: %ld bytes past end of buffer!                  |\n",
               (long)(s->cur - correct));
        printf("  |                                                           |\n");
        printf("  |  FIX: 'out->cur = out->cur + out->l;'                    |\n");
        printf("  |   ->  'out->cur = out->cur + b1_len;'                    |\n");
        printf("  +-----------------------------------------------------------+\n");
        printf(C_RESET "\n");
        _tf_failed++;
        csorma_str_free(s);
        return false;
    }
    csorma_str_free(s);
    return true;
}

static bool t_con_cur_never_oob(void) {
    csorma_s *s = csorma_str2_build("x");
    for (int i = 0; i < 20; i++) {
        s = csorma_str_con(s, "YYYY", 4);
        long off = s->cur - s->s;
        if (off < 0 || off > (long)s->l) {
            printf("         iter %d: cur offset=%ld, max=%u OOB!\n", i, off, s->l);
            _tf_failed++;
            csorma_str_free(s);
            return false;
        }
    }
    csorma_str_free(s);
    return true;
}

static bool t_con_cur_after_empty(void) {
    csorma_s *s = csorma_str2_build("hello");
    s = csorma_str_con(s, "", 0);
    T_ASSERT_PTR_EQ(s->cur, s->s + s->l, "cur after empty concat");
    csorma_str_free(s);
    return true;
}

/* ============================================================
 *  csorma_str_con2() tests
 * ============================================================ */
static bool t_con2_basic(void) {
    csorma_s *a = csorma_str2_build("hello");
    csorma_s *b = csorma_str2_build(" world");
    a = csorma_str_con2(a, b);
    T_ASSERT_INT_EQ(a->l, 11, "len=11");
    T_ASSERT_MEM_EQ(a->s, "hello world", 11, "content");
    csorma_str_free(a);
    csorma_str_free(b);
    return true;
}

static bool t_con2_null_append(void) {
    csorma_s *a = csorma_str2_build("hello");
    a = csorma_str_con2(a, NULL);
    T_ASSERT_INT_EQ(a->l, 5, "unchanged");
    csorma_str_free(a);
    return true;
}

static bool t_con2_null_base(void) {
    csorma_s *b = csorma_str2_build("world");
    csorma_s *a = csorma_str_con2(NULL, b);
    T_ASSERT_INT_EQ(a->l, 5, "len=5");
    T_ASSERT_MEM_EQ(a->s, "world", 5, "content");
    csorma_str_free(a);
    csorma_str_free(b);
    return true;
}

/* ============================================================
 *  csorma_str_con_space() tests
 * ============================================================ */
static bool t_con_space(void) {
    csorma_s *s = csorma_str2_build("hello");
    s = csorma_str_con_space(s);
    s = csorma_str_con(s, "world", 5);
    T_ASSERT_INT_EQ(s->l, 11, "len=11");
    T_ASSERT_MEM_EQ(s->s, "hello world", 11, "content");
    csorma_str_free(s);
    return true;
}

/* ============================================================
 *  csorma_str_int32t() tests
 * ============================================================ */
static bool t_int32_pos(void) {
    csorma_s *s = csorma_str2_build("");
    s = csorma_str_int32t(s, 12345);
    T_ASSERT_STR_EQ(s->s, "12345", "positive");
    csorma_str_free(s);
    return true;
}
static bool t_int32_neg(void) {
    csorma_s *s = csorma_str2_build("");
    s = csorma_str_int32t(s, -42);
    T_ASSERT_STR_EQ(s->s, "-42", "negative");
    csorma_str_free(s);
    return true;
}
static bool t_int32_zero(void) {
    csorma_s *s = csorma_str2_build("");
    s = csorma_str_int32t(s, 0);
    T_ASSERT_STR_EQ(s->s, "0", "zero");
    csorma_str_free(s);
    return true;
}
static bool t_int32_max(void) {
    csorma_s *s = csorma_str2_build("");
    s = csorma_str_int32t(s, 2147483647);
    T_ASSERT_STR_EQ(s->s, "2147483647", "INT32_MAX");
    csorma_str_free(s);
    return true;
}
static bool t_int32_min(void) {
    csorma_s *s = csorma_str2_build("");
    s = csorma_str_int32t(s, -2147483647 - 1);
    T_ASSERT_STR_EQ(s->s, "-2147483648", "INT32_MIN");
    csorma_str_free(s);
    return true;
}

/* ============================================================
 *  csorma_str_free() tests
 * ============================================================ */
static bool t_free_null(void) {
    csorma_str_free(NULL);
    return true;
}

static bool t_free_after_growth(void) {
    csorma_s *s = csorma_str2_build("");
    for (int i = 0; i < 1000; i++)
        s = csorma_str_con(s, "abcdefghij", 10);
    T_ASSERT_INT_EQ(s->l, 10000, "len=10000");
    csorma_str_free(s);
    return true;
}

/* ============================================================
 *  MAIN
 * ============================================================ */
int main(void) {
    printf(C_BOLD "\n");
    printf("  ================================================================\n");
    printf("   CSORMA STRING UTILITY UNIT TESTS\n");
    printf("   Source: ../template/csorma.c (compiled directly)\n");
    printf("  ================================================================\n");
    printf(C_RESET "\n");

    TEST_SUITE("csorma_str2_build");
    RUN_TEST(t_build_basic);
    RUN_TEST(t_build_empty);
    RUN_TEST(t_build_null);
    RUN_TEST(t_build_single_char);
    RUN_TEST(t_build_long);
    SUITE_END();

    TEST_SUITE("csorma_str_build");
    RUN_TEST(t_build_len_basic);
    RUN_TEST(t_build_len_zero);
    RUN_TEST(t_build_len_partial);
    RUN_TEST(t_build_len_binary);
    RUN_TEST(t_build_len_256);
    SUITE_END();

    TEST_SUITE("csorma_str_con");
    RUN_TEST(t_con_basic);
    RUN_TEST(t_con_null);
    RUN_TEST(t_con_empty_append);
    RUN_TEST(t_con_to_empty);
    RUN_TEST(t_con_sequential);
    RUN_TEST(t_con_many_small);
    RUN_TEST(t_con_binary);
    RUN_TEST(t_con_large);
    SUITE_END();

    TEST_SUITE("csorma_str_con — POINTER BUG");
    RUN_TEST(t_con_cur_pointer);
    RUN_TEST(t_con_cur_never_oob);
    RUN_TEST(t_con_cur_after_empty);
    SUITE_END();

    TEST_SUITE("csorma_str_con2");
    RUN_TEST(t_con2_basic);
    RUN_TEST(t_con2_null_append);
    RUN_TEST(t_con2_null_base);
    SUITE_END();

    TEST_SUITE("csorma_str_con_space");
    RUN_TEST(t_con_space);
    SUITE_END();

    TEST_SUITE("csorma_str_int32t");
    RUN_TEST(t_int32_pos);
    RUN_TEST(t_int32_neg);
    RUN_TEST(t_int32_zero);
    RUN_TEST(t_int32_max);
    RUN_TEST(t_int32_min);
    SUITE_END();

    TEST_SUITE("csorma_str_free");
    RUN_TEST(t_free_null);
    RUN_TEST(t_free_after_growth);
    SUITE_END();

    return test_summary("String Utilities");
}
