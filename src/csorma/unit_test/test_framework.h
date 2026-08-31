/*
 * test_framework.h — Minimal visual test framework for csorma
 */
#ifndef TEST_FRAMEWORK_H
#define TEST_FRAMEWORK_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>

#ifdef __linux__
#define C_RED     "\033[1;31m"
#define C_GREEN   "\033[1;32m"
#define C_YELLOW  "\033[1;33m"
#define C_BLUE    "\033[1;34m"
#define C_CYAN    "\033[1;36m"
#define C_BOLD    "\033[1m"
#define C_RESET   "\033[0m"
#else
#define C_RED ""
#define C_GREEN ""
#define C_YELLOW ""
#define C_BLUE ""
#define C_CYAN ""
#define C_BOLD ""
#define C_RESET ""
#endif

static int _tf_total = 0, _tf_passed = 0, _tf_failed = 0, _tf_skipped = 0;
static const char *_tf_suite = "";
static clock_t _tf_t0 = 0;

#define TEST_SUITE(name) do { \
    _tf_suite = name; _tf_t0 = clock(); \
    printf("\n" C_CYAN C_BOLD \
    "  +============================================================+\n" \
    "  |  SUITE: %-52s|\n" \
    "  +============================================================+\n" C_RESET, name); \
} while(0)

#define SUITE_END() do { \
    double _e = (double)(clock()-_tf_t0)/CLOCKS_PER_SEC; \
    printf(C_CYAN "  +---- %s done (%.3fs) ----+\n" C_RESET, _tf_suite, _e); \
} while(0)

#define RUN_TEST(fn) do { \
    int _of = _tf_failed; \
    clock_t _t = clock(); \
    bool _r = fn(); \
    double _e = (double)(clock()-_t)/CLOCKS_PER_SEC; \
    _tf_total++; \
    if (_r && _tf_failed == _of) { _tf_passed++; \
        printf(C_GREEN "  [PASS]" C_RESET " %-48s (%.3fs)\n", #fn, _e); \
    } else { \
        printf(C_RED "  [FAIL]" C_RESET " %-48s (%.3fs)\n", #fn, _e); \
    } \
} while(0)

#define T_ASSERT(cond, msg) do { if (!(cond)) { \
    printf(C_RED "         FAIL: %s\n         Cond: %s\n         %s:%d\n" C_RESET, \
           msg, #cond, __FILE__, __LINE__); \
    _tf_failed++; return false; } } while(0)

#define T_ASSERT_INT_EQ(a, e, msg) do { \
    long long _a=(long long)(a), _e=(long long)(e); \
    if (_a != _e) { \
    printf(C_RED "         FAIL: %s\n         Expected: %lld  Actual: %lld\n         %s:%d\n" C_RESET, \
           msg, _e, _a, __FILE__, __LINE__); \
    _tf_failed++; return false; } } while(0)

#define T_ASSERT_PTR_EQ(a, e, msg) do { \
    void *_a=(void*)(a), *_e=(void*)(e); \
    if (_a != _e) { \
    printf(C_RED "         FAIL: %s\n         Expected: %p  Actual: %p  Delta: %ld\n         %s:%d\n" C_RESET, \
           msg, _e, _a, (long)((char*)_a-(char*)_e), __FILE__, __LINE__); \
    _tf_failed++; return false; } } while(0)

#define T_ASSERT_PTR_NOT_NULL(p, msg) do { if ((p)==NULL) { \
    printf(C_RED "         FAIL: %s (NULL)\n         %s:%d\n" C_RESET, msg, __FILE__, __LINE__); \
    _tf_failed++; return false; } } while(0)

#define T_ASSERT_PTR_NULL(p, msg) do { if ((p)!=NULL) { \
    printf(C_RED "         FAIL: %s (expected NULL, got %p)\n         %s:%d\n" C_RESET, \
           msg, (void*)(p), __FILE__, __LINE__); \
    _tf_failed++; return false; } } while(0)

#define T_ASSERT_MEM_EQ(a, e, len, msg) do { \
    if (memcmp((a),(e),(len))!=0) { \
    printf(C_RED "         FAIL: %s (memcmp, %zu bytes)\n" C_RESET, msg, (size_t)(len)); \
    printf(C_RED "         Expected: "); \
    for (size_t _i=0;_i<(size_t)(len)&&_i<32;_i++) printf("%02x ",((const uint8_t*)(e))[_i]); \
    printf("\n         Actual:   "); \
    for (size_t _i=0;_i<(size_t)(len)&&_i<32;_i++) printf("%02x ",((const uint8_t*)(a))[_i]); \
    printf("\n         %s:%d\n" C_RESET, __FILE__, __LINE__); \
    _tf_failed++; return false; } } while(0)

#define T_ASSERT_STR_EQ(a, e, msg) do { \
    if (strcmp((const char*)(a),(e))!=0) { \
    printf(C_RED "         FAIL: %s\n         Expected: \"%s\"\n         Actual:   \"%s\"\n         %s:%d\n" C_RESET, \
           msg, (e), (const char*)(a), __FILE__, __LINE__); \
    _tf_failed++; return false; } } while(0)

static inline int test_summary(const char *name) {
    printf("\n" C_BOLD "  ==============================================================\n");
    printf("    RESULTS: %s\n", name);
    printf("  ==============================================================\n" C_RESET);
    printf("    Total:   %d\n", _tf_total);
    printf(C_GREEN "    Passed:  %d\n" C_RESET, _tf_passed);
    if (_tf_failed) printf(C_RED "    Failed:  %d\n" C_RESET, _tf_failed);
    else printf("    Failed:  0\n");
    printf("  ==============================================================\n");
    if (_tf_failed) printf(C_RED C_BOLD "    >>> FAILED <<<\n" C_RESET);
    else printf(C_GREEN C_BOLD "    >>> ALL PASSED <<<\n" C_RESET);
    printf("  ==============================================================\n\n");
    return _tf_failed > 0 ? 1 : 0;
}

#endif /* TEST_FRAMEWORK_H */
