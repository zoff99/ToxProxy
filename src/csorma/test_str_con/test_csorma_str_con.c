/*
 * test_csorma_str_con.c
 * =====================
 * Comprehensive unit tests for csorma_str_con() from the csorma project.
 * Tests the ORIGINAL (buggy) and a FIXED implementation side by side.
 *
 * Compile:  gcc -std=c99 -Wall -Wextra -g -o test_csorma_str_con test_csorma_str_con.c
 * Run:      ./test_csorma_str_con
 *
 * With ASAN: gcc -std=c99 -Wall -Wextra -g -fsanitize=address -o test test_csorma_str_con.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

/* ============================================================
 *  csorma types (from the project)
 * ============================================================ */
typedef struct csorma_s {
    uint8_t* cur;      /* "current" position pointer */
    uint32_t l;        /* length of content (excluding NUL terminator) */
    uint8_t  n;        /* NUL terminator present flag */
    uint8_t* s;        /* the actual buffer */
} csorma_s;

/* ============================================================
 *  ORIGINAL (BUGGY) implementation — copied from csorma project
 *
 *  The bug is the last line before "return":
 *    out->cur = out->cur + out->l;
 *  This adds the TOTAL length to the old cur position, producing
 *  a pointer that is (old_length) bytes PAST the end of the buffer.
 * ============================================================ */
csorma_s *csorma_str_con_BUGGY(csorma_s *out, const char *b1, const uint32_t b1_len)
{
    if (out == NULL)
    {
        out = calloc(1, sizeof(csorma_s));
    }

    out->s = realloc(out->s, out->l + b1_len + 1);
    if (out->s == NULL)
    {
        fprintf(stderr, "!! PANIC !!\n");
    }
    out->cur = out->s + out->l;
    memset(out->cur, 0, b1_len + 1);
    memcpy(out->cur, b1, b1_len);
    out->l = out->l + b1_len;
    out->cur = out->cur + out->l;    /* <=== BUG: should be + b1_len */
    out->n = 1;
    return out;
}

/* ============================================================
 *  FIXED implementation
 * ============================================================ */
csorma_s *csorma_str_con_FIXED(csorma_s *out, const char *b1, const uint32_t b1_len)
{
    if (out == NULL)
    {
        out = calloc(1, sizeof(csorma_s));
        if (out == NULL) return NULL;
    }

    uint8_t *tmp = realloc(out->s, out->l + b1_len + 1);
    if (tmp == NULL)
    {
        fprintf(stderr, "!! PANIC: realloc failed !!\n");
        return out;  /* original data preserved */
    }
    out->s = tmp;

    out->cur = out->s + out->l;
    memset(out->cur, 0, b1_len + 1);
    memcpy(out->cur, b1, b1_len);
    out->l = out->l + b1_len;
    out->cur = out->cur + b1_len;    /* <=== FIXED */
    out->n = 1;
    return out;
}

/* Active implementation under test */
typedef csorma_s *(*concat_fn)(csorma_s*, const char*, uint32_t);
static concat_fn active_impl = csorma_str_con_BUGGY;

/* ============================================================
 *  Helper functions
 * ============================================================ */
csorma_s *csorma_str2_build(const char *b1)
{
    if (b1 == NULL) return NULL;
    uint32_t len = strlen(b1);
    csorma_s *out = calloc(1, sizeof(csorma_s));
    if (!out) return NULL;
    out->s = calloc(1, len + 1);
    if (!out->s) { free(out); return NULL; }
    memcpy(out->s, b1, len);
    out->l = len;
    out->cur = out->s + len;
    out->n = 1;
    return out;
}

csorma_s *csorma_str_build(const char *b1, uint32_t len)
{
    csorma_s *out = calloc(1, sizeof(csorma_s));
    if (!out) return NULL;
    out->s = calloc(1, len + 1);
    if (!out->s) { free(out); return NULL; }
    memcpy(out->s, b1, len);
    out->l = len;
    out->cur = out->s + len;
    out->n = 1;
    return out;
}

void csorma_str_free(csorma_s *s)
{
    if (!s) return;
    free(s->s);
    free(s);
}

/* ============================================================
 *  Visual Explanation Printer
 * ============================================================ */
static void print_bug_visual_explanation(csorma_s *before, csorma_s *after)
{
    printf("\n");
    printf("    +-------------------------------------------------------------+\n");
    printf("    |                  THE BUG EXPLAINED VISUALLY                 |\n");
    printf("    +-------------------------------------------------------------+\n");
    printf("    |                                                             |\n");
    printf("    |  BEFORE concat (after csorma_str2_build(\"hello\")):         |\n");
    printf("    |                                                             |\n");
    printf("    |  Buffer:  [h][e][l][l][o][\\0]                              |\n");
    printf("    |           [0][1][2][3][4][5]    6 bytes allocated           |\n");
    printf("    |  s   = %p                                               |\n", (void*)before->s);
    printf("    |  l   = %u                                                    |\n", before->l);
    printf("    |  cur = %p   (s + %u = points to NUL terminator)    |\n",
           (void*)before->cur, before->l);
    printf("    |                                                             |\n");
    printf("    +-------------------------------------------------------------+\n");
    printf("    |                                                             |\n");
    printf("    |  AFTER concat(\" world\", 6):                                |\n");
    printf("    |                                                             |\n");
    printf("    |  Buffer:  [h][e][l][l][o][ ][w][o][r][l][d][\\0]           |\n");
    printf("    |           [0][1][2][3][4][5][6][7][8][9][A][B]  12 bytes    |\n");
    printf("    |  s   = %p                                               |\n", (void*)after->s);
    printf("    |  l   = %u                                                   |\n", after->l);
    printf("    |                                                             |\n");
    printf("    |  CORRECT cur = s + %2u  = %p   (points to NUL)     |\n",
           after->l, (void*)(after->s + after->l));
    printf("    |  BUGGY   cur = (s+%u) + %u = %p                          |\n",
           before->l, after->l, (void*)after->cur);
    printf("    |                  ^^^^^^^^^^^^                                |\n");
    printf("    |                  old_l + new_l (WRONG!)                     |\n");
    printf("    |                                                             |\n");

    long delta = (long)(after->cur - (after->s + after->l));
    if (delta > 0) {
        printf("    |  RESULT: cur is %ld bytes PAST THE END OF THE BUFFER!        |\n", delta);
        printf("    |                                                             |\n");
        printf("    |  +---+---+---+---+---+---+---+---+---+---+---+---+          |\n");
        printf("    |  | h | e | l | l | o |   | w | o | r | l | d |\\0|          |\n");
        printf("    |  +---+---+---+---+---+---+---+---+---+---+---+---+          |\n");
        printf("    |    0   1   2   3   4   5   6   7   8   9  10  11            |\n");
        printf("    |                                      ^ correct cur (s+11)   |\n");
        printf("    |                                                          ^  |\n");
        printf("    |                                      buggy cur (s+%2ld)    |\n", after->l + delta);
        printf("    |                                          |                  |\n");
        printf("    |                                          +--- OUT OF BOUNDS |\n");
    }
    printf("    |                                                             |\n");
    printf("    +-------------------------------------------------------------+\n");
    printf("    |                                                             |\n");
    printf("    |  ROOT CAUSE (in csorma.c, csorma_str_con function):         |\n");
    printf("    |                                                             |\n");
    printf("    |    out->l = out->l + b1_len;                                |\n");
    printf("    |    out->cur = out->cur + out->l;  // <-- BUG IS HERE       |\n");
    printf("    |                                                             |\n");
    printf("    |  'out->cur' at this point still holds the OLD cur value:    |\n");
    printf("    |  s + old_l.  Adding 'out->l' (which is now old_l + b1_len) |\n");
    printf("    |  gives: s + old_l + old_l + b1_len                          |\n");
    printf("    |  Instead of the correct: s + old_l + b1_len                |\n");
    printf("    |                                                             |\n");
    printf("    |  FIX:                                                       |\n");
    printf("    |    out->cur = out->cur + b1_len;   // <-- use b1_len        |\n");
    printf("    |                                                             |\n");
    printf("    +-------------------------------------------------------------+\n");
    printf("    |                                                             |\n");
    printf("    |  WHY IT DOESN'T CRASH IN PRACTICE:                          |\n");
    printf("    |                                                             |\n");
    printf("    |  The function resets cur correctly at the START of each     |\n");
    printf("    |  call:                                                      |\n");
    printf("    |                                                             |\n");
    printf("    |    out->cur = out->s + out->l;   // fixes it for next call |\n");
    printf("    |                                                             |\n");
    printf("    |  So cur is only wrong BETWEEN calls. If nobody reads        |\n");
    printf("    |  str->cur between csorma_str_con() calls, data is intact.   |\n");
    printf("    |  But any future code that uses cur will get an              |\n");
    printf("    |  out-of-bounds pointer.                                     |\n");
    printf("    |                                                             |\n");
    printf("    +-------------------------------------------------------------+\n");
    printf("\n");
}

/* ============================================================
 *  Test framework
 * ============================================================ */
static int t_run = 0, t_pass = 0, t_fail = 0;
static bool visual_explained = false;

#define CHECK(cond, msg) do { \
    t_run++; \
    if (!(cond)) { \
        printf("    FAIL: %s\n", msg); \
        t_fail++; \
    } else { \
        t_pass++; \
    } \
} while(0)

#define CHECK_INT(a, e, msg) do { \
    t_run++; \
    if ((long)(a) != (long)(e)) { \
        printf("    FAIL: %s (expected=%ld got=%ld)\n", msg, (long)(e), (long)(a)); \
        t_fail++; \
    } else { t_pass++; } \
} while(0)

#define CHECK_PTR(a, e, msg) do { \
    t_run++; \
    if ((a) != (e)) { \
        printf("    FAIL: %s (expected=%p got=%p delta=%ld)\n", \
               msg, (void*)(e), (void*)(a), (long)((char*)(a)-(char*)(e))); \
        t_fail++; \
    } else { t_pass++; } \
} while(0)

static int run_test(const char *name, bool (*fn)(void)) {
    int old_fail = t_fail;
    printf("  %-42s", name);
    fflush(stdout);
    bool ok = fn();
    if (ok && t_fail == old_fail) {
        printf("OK\n");
        return 0;
    } else {
        printf("FAILED\n");
        return 1;
    }
}

#define TEST(n) run_test(#n, n)

/* ============================================================
 *  TEST CASES
 * ============================================================ */

/* ---------- Functional tests ---------- */

static bool t01_basic_concat(void) {
    csorma_s *s = csorma_str2_build("hello");
    s = active_impl(s, " world", 6);
    CHECK(s->l == 11, "length==11");
    CHECK(memcmp(s->s, "hello world", 11) == 0, "content");
    CHECK(s->s[11] == '\0', "NUL terminator");
    csorma_str_free(s);
    return true;
}

static bool t02_concat_onto_null(void) {
    csorma_s *s = NULL;
    s = active_impl(s, "fresh", 5);
    CHECK(s != NULL, "not null");
    CHECK(s->l == 5, "length==5");
    CHECK(memcmp(s->s, "fresh", 5) == 0, "content");
    csorma_str_free(s);
    return true;
}

static bool t03_concat_empty(void) {
    csorma_s *s = csorma_str2_build("hello");
    s = active_impl(s, "", 0);
    CHECK(s->l == 5, "length unchanged");
    CHECK(memcmp(s->s, "hello", 5) == 0, "content unchanged");
    csorma_str_free(s);
    return true;
}

static bool t04_concat_to_empty(void) {
    csorma_s *s = csorma_str2_build("");
    s = active_impl(s, "hello", 5);
    CHECK(s->l == 5, "length==5");
    CHECK(memcmp(s->s, "hello", 5) == 0, "content");
    csorma_str_free(s);
    return true;
}

static bool t05_multiple_concat(void) {
    csorma_s *s = csorma_str2_build("a");
    s = active_impl(s, "b", 1);
    s = active_impl(s, "c", 1);
    s = active_impl(s, "d", 1);
    s = active_impl(s, "e", 1);
    s = active_impl(s, "f", 1);
    CHECK(s->l == 6, "length==6");
    CHECK(memcmp(s->s, "abcdef", 6) == 0, "content");
    csorma_str_free(s);
    return true;
}

static bool t06_binary_nul(void) {
    const char bin[] = {'A', '\0', 'B', '\0', 'C'};
    csorma_s *s = csorma_str_build(bin, 5);
    s = active_impl(s, "\0\0", 2);
    CHECK_INT(s->l, 7, "length");
    CHECK(s->s[0] == 'A' && s->s[1] == '\0' && s->s[2] == 'B' &&
          s->s[3] == '\0' && s->s[4] == 'C' && s->s[5] == '\0' &&
          s->s[6] == '\0', "binary data preserved");
    csorma_str_free(s);
    return true;
}

static bool t07_large_concat(void) {
    csorma_s *s = csorma_str2_build("");
    uint32_t sz = 1024 * 1024;
    char *big = calloc(1, sz);
    memset(big, 'X', sz);
    s = active_impl(s, big, sz);
    CHECK_INT(s->l, sz, "1MB length");
    bool ok = true;
    for (uint32_t i = 0; i < s->l && i < 10000; i++)
        if (s->s[i] != 'X') { ok = false; break; }
    CHECK(ok, "data correct");
    free(big);
    csorma_str_free(s);
    return true;
}

static bool t08_many_small(void) {
    csorma_s *s = csorma_str2_build("");
    for (int i = 0; i < 10000; i++)
        s = active_impl(s, ".", 1);
    CHECK_INT(s->l, 10000, "10000 dots");
    csorma_str_free(s);
    return true;
}

static bool t09_all_bytes(void) {
    uint8_t buf[256];
    for (int i = 0; i < 256; i++) buf[i] = (uint8_t)i;
    csorma_s *s = csorma_str_build("", 0);
    s = active_impl(s, (const char*)buf, 256);
    CHECK_INT(s->l, 256, "length==256");
    bool ok = true;
    for (int i = 0; i < 256; i++)
        if (s->s[i] != (uint8_t)i) { ok = false; break; }
    CHECK(ok, "all 256 byte values");
    csorma_str_free(s);
    return true;
}

static bool t10_nul_terminator(void) {
    csorma_s *s = csorma_str2_build("test");
    CHECK(s->s[s->l] == '\0', "NUL after build");
    s = active_impl(s, "ing", 3);
    CHECK(s->s[s->l] == '\0', "NUL after concat 1");
    s = active_impl(s, "123", 3);
    CHECK(s->s[s->l] == '\0', "NUL after concat 2");
    s = active_impl(s, "", 0);
    CHECK(s->s[s->l] == '\0', "NUL after empty concat");
    csorma_str_free(s);
    return true;
}

static bool t11_char_at_a_time(void) {
    csorma_s *s = csorma_str2_build("");
    for (int r = 0; r < 100; r++)
        for (int i = 0; i < 26; i++)
            s = active_impl(s, &"abcdefghijklmnopqrstuvwxyz"[i], 1);
    CHECK_INT(s->l, 2600, "length==2600");
    CHECK(memcmp(s->s, "abcdefghijklmnopqrstuvwxyz", 26) == 0, "first round");
    csorma_str_free(s);
    return true;
}

static bool t12_data_integrity(void) {
    csorma_s *s = csorma_str2_build("");
    s = active_impl(s, "alpha", 5);
    s = active_impl(s, "beta", 4);
    s = active_impl(s, "gamma", 5);
    s = active_impl(s, "delta", 5);
    CHECK(s->l == 19, "length==19");
    CHECK(memcmp(s->s, "alphabetagammadelta", 19) == 0, "content");
    csorma_str_free(s);
    return true;
}

static bool t13_alternating(void) {
    csorma_s *s = csorma_str2_build("X");
    s = active_impl(s, "", 0);
    s = active_impl(s, "Y", 1);
    s = active_impl(s, "", 0);
    s = active_impl(s, "", 0);
    s = active_impl(s, "Z", 1);
    s = active_impl(s, "", 0);
    CHECK(s->l == 3, "length==3");
    CHECK(memcmp(s->s, "XYZ", 3) == 0, "content");
    csorma_str_free(s);
    return true;
}

static bool t14_realloc_growth(void) {
    csorma_s *s = csorma_str2_build("");
    for (int i = 0; i < 500; i++) {
        char chunk[32];
        int len = snprintf(chunk, sizeof(chunk), "[%04d]", i);
        s = active_impl(s, chunk, (uint32_t)len);
    }
    CHECK(memcmp(s->s, "[0000]", 6) == 0, "starts right");
    CHECK(memcmp(s->s + s->l - 6, "[0499]", 6) == 0, "ends right");
    csorma_str_free(s);
    return true;
}

/* ---------- Pointer arithmetic / bug tests ---------- */

static bool t15_cur_after_single_concat(void) {
    csorma_s *before = csorma_str2_build("hello");
    /* Save a copy of the "before" state for the visual explanation */
    csorma_s before_copy = *before;
    
    csorma_s *after = active_impl(before, " world", 6);
    
    uint8_t *expected = after->s + after->l;
    CHECK_PTR(after->cur, expected, "cur should be s+l");
    
    /* If we're testing the BUGGY impl and it failed, show the visual */
    if (active_impl == csorma_str_con_BUGGY && after->cur != expected && !visual_explained) {
        print_bug_visual_explanation(&before_copy, after);
        visual_explained = true;
    }
    
    csorma_str_free(after);
    return true;
}

static bool t16_cur_after_multiple_concats(void) {
    csorma_s *s = csorma_str2_build("aa");
    s = active_impl(s, "bb", 2);
    CHECK_PTR(s->cur, s->s + s->l, "cur after 'aa'+'bb'");

    s = active_impl(s, "cc", 2);
    CHECK_PTR(s->cur, s->s + s->l, "cur after +\"cc\"");

    s = active_impl(s, "dd", 2);
    CHECK_PTR(s->cur, s->s + s->l, "cur after +\"dd\"");

    csorma_str_free(s);
    return true;
}

static bool t17_cur_never_oob(void) {
    csorma_s *s = csorma_str2_build("start");
    bool any_oob = false;
    for (int i = 0; i < 20; i++) {
        s = active_impl(s, "XXXX", 4);
        long off = s->cur - s->s;
        if (off < 0 || off > (long)s->l) {
            if (!any_oob) {
                printf("    iter %d: cur at offset %ld, buffer [0..%u] OUT OF BOUNDS!\n",
                       i, off, s->l);
            }
            any_oob = true;
        }
    }
    CHECK(!any_oob, "cur always within [s, s+l]");
    csorma_str_free(s);
    return true;
}

static bool t18_cur_after_empty_concat(void) {
    csorma_s *s = csorma_str2_build("hello");
    s = active_impl(s, "", 0);
    CHECK_PTR(s->cur, s->s + s->l, "cur after empty concat");
    csorma_str_free(s);
    return true;
}

static bool t19_cur_on_null_input(void) {
    csorma_s *s = NULL;
    s = active_impl(s, "hello", 5);
    CHECK_PTR(s->cur, s->s + s->l, "cur on fresh string");
    csorma_str_free(s);
    return true;
}

static bool t20_cur_after_large_concat(void) {
    csorma_s *s = csorma_str2_build("X");
    uint32_t big = 10000;
    char *buf = calloc(1, big);
    memset(buf, 'Y', big);
    s = active_impl(s, buf, big);
    CHECK_PTR(s->cur, s->s + s->l, "cur after large concat");
    CHECK(s->s[0] == 'X' && s->s[1] == 'Y' && s->s[big] == 'Y', "content");
    free(buf);
    csorma_str_free(s);
    return true;
}

/* ============================================================
 *  MAIN
 * ============================================================ */
static void run_all(void) {
    printf("  --- Functional tests ---\n");
    TEST(t01_basic_concat);
    TEST(t02_concat_onto_null);
    TEST(t03_concat_empty);
    TEST(t04_concat_to_empty);
    TEST(t05_multiple_concat);
    TEST(t06_binary_nul);
    TEST(t07_large_concat);
    TEST(t08_many_small);
    TEST(t09_all_bytes);
    TEST(t10_nul_terminator);
    TEST(t11_char_at_a_time);
    TEST(t12_data_integrity);
    TEST(t13_alternating);
    TEST(t14_realloc_growth);

    printf("\n  --- Pointer arithmetic tests (THE BUG) ---\n");
    TEST(t15_cur_after_single_concat);
    TEST(t16_cur_after_multiple_concats);
    TEST(t17_cur_never_oob);
    TEST(t18_cur_after_empty_concat);
    TEST(t19_cur_on_null_input);
    TEST(t20_cur_after_large_concat);
}

int main(void) {
    printf("================================================================\n");
    printf("  csorma_str_con() -- Unit Test Suite\n");
    printf("  Repository: https://github.com/zoff99/csorma/\n");
    printf("  File under test: template/csorma.c -> csorma_str_con()\n");
    printf("================================================================\n\n");

    /* ---- BUGGY ---- */
    printf("--------------------------------------------------------------\n");
    printf("  PART 1: ORIGINAL (BUGGY) implementation\n");
    printf("  (line from csorma.c: out->cur = out->cur + out->l;)\n");
    printf("--------------------------------------------------------------\n");
    active_impl = csorma_str_con_BUGGY;
    t_run = t_pass = t_fail = 0;
    visual_explained = false;
    run_all();
    int buggy_fail = t_fail;
    printf("\n  BUGGY total: %d/%d passed, %d FAILED\n", t_pass, t_run, t_fail);

    /* ---- FIXED ---- */
    printf("\n--------------------------------------------------------------\n");
    printf("  PART 2: FIXED implementation\n");
    printf("  (line: out->cur = out->cur + b1_len;)\n");
    printf("--------------------------------------------------------------\n");
    active_impl = csorma_str_con_FIXED;
    t_run = t_pass = t_fail = 0;
    run_all();
    int fixed_fail = t_fail;
    printf("\n  FIXED total: %d/%d passed, %d FAILED\n", t_pass, t_run, t_fail);

    /* ---- SUMMARY ---- */
    printf("\n================================================================\n");
    printf("  FINAL SUMMARY\n");
    printf("================================================================\n");
    printf("  BUGGY implementation: %d test assertions FAILED\n", buggy_fail);
    printf("  FIXED implementation: %d test assertions FAILED\n", fixed_fail);
    printf("\n");
    if (buggy_fail > 0 && fixed_fail == 0) {
        printf("  VERDICT: BUG CONFIRMED AND FIX VALIDATED\n\n");
        printf("  The original code has:\n");
        printf("    out->cur = out->cur + out->l;\n");
        printf("  This should be:\n");
        printf("    out->cur = out->cur + b1_len;\n");
        printf("\n");
        printf("  Impact: 'cur' becomes a dangling out-of-bounds pointer.\n");
        printf("  In the current codebase this is masked because cur is\n");
        printf("  reset at the START of each csorma_str_con() call.\n");
        printf("  But any code reading 'cur' between calls will get a\n");
        printf("  pointer past the end of the allocated buffer.\n");
    } else if (buggy_fail == 0 && fixed_fail == 0) {
        printf("  Both implementations pass all tests.\n");
        printf("  (The bug may have already been fixed in the codebase.)\n");
    } else if (fixed_fail > 0) {
        printf("  WARNING: Fixed implementation still has failures.\n");
        printf("  The fix may be incomplete.\n");
    }
    printf("================================================================\n");

    return (fixed_fail > 0) ? 1 : 0;
}
