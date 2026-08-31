#!/bin/bash
# run_sanitized.sh — Run all tests with ASAN, TSAN, and UBSAN
set -e

echo "================================================================"
echo "  CSORMA UNIT TESTS — SANITIZED BUILDS"
echo "================================================================"

FAILURES=0

echo ""
echo ">>> ADDRESS SANITIZER (memory errors, leaks, OOB)"
echo "----------------------------------------------------------------"
make clean >/dev/null 2>&1
if make asan_all 2>&1; then
    echo "  ASAN: PASS"
else
    echo "  ASAN: FAIL"
    FAILURES=$((FAILURES+1))
fi

echo ""
echo ">>> THREAD SANITIZER (data races)"
echo "----------------------------------------------------------------"
make clean >/dev/null 2>&1
if make tsan_all 2>&1; then
    echo "  TSAN: PASS"
else
    echo "  TSAN: FAIL"
    FAILURES=$((FAILURES+1))
fi

echo ""
echo ">>> UNDEFINED BEHAVIOR SANITIZER"
echo "----------------------------------------------------------------"
make clean >/dev/null 2>&1
if make ubsan_all 2>&1; then
    echo "  UBSAN: PASS"
else
    echo "  UBSAN: FAIL"
    FAILURES=$((FAILURES+1))
fi

echo ""
echo "================================================================"
if [ $FAILURES -eq 0 ]; then
    echo "  ALL SANITIZED BUILDS PASSED"
else
    echo "  $FAILURES SANITIZED BUILD(S) FAILED"
fi
echo "================================================================"
exit $FAILURES
