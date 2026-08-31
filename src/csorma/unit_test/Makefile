#
# unit_test/Makefile
# ==================
# Builds unit tests directly against ../template/csorma.c (the real code).
# No fragile extraction — tests always run against current source.
#
# When the template code changes, simply re-run 'make test_all' and all
# tests automatically exercise the updated code.
#
# Build errors stop immediately. Test failures do NOT stop other tests.
#
# Usage:
#   make test_all          - build and run all tests
#   make test_str          - string utility tests
#   make test_bind         - bindvar tests
#   make test_db           - database operation tests
#   make test_schema       - schema upgrade tests
#   make test_resultset    - result set tests
#   make test_thread       - threading / concurrency tests
#   make test_clauses      - SQL clause building tests
#   make test_column       - column lookup tests (rs_find_column_idx)
#   make test_logger       - logger edge case tests
#   make test_busy         - SQLITE_BUSY handling tests
#   make test_leaks        - memory leak lifecycle tests
#   make test_bind_stmt    - bindvar_to_stmt / bind_all_* tests
#   make test_error        - error recovery tests
#   make test_lifetime     - SQLITE_STATIC binding lifetime tests
#   make test_coercion     - type coercion in result reading tests
#   make test_path         - str_buf_concat path building tests
#   make test_str_con_null - csorma_str_con NULL b1 tests
#   make test_unicode      - unicode & special character tests
#   make asan_all          - all tests with AddressSanitizer
#   make tsan_all          - all tests with ThreadSanitizer
#   make ubsan_all         - all tests with UBSanitizer
#   make clean             - remove generated files
#

SHELL        := /bin/bash
TEMPLATE_DIR := ../template
SQLITE_DIR   := ../sqlite
BUILD_DIR    := ./_build
BIN_DIR      := ./_bin

CC     ?= gcc
AR     ?= ar

# Base compiler flags for all builds.
# -I.. allows #include "sqlite/sqlite3.h" to resolve from the repo root.
# -I$(TEMPLATE_DIR) allows #include "csorma.h" and #include "logger.h".
# -I$(SQLITE_DIR) allows #include "sqlite3.h" directly.
CFLAGS := -std=c99 -Wall -Wextra -Wno-unused-function -Wno-unused-parameter \
          -Wno-unused-variable -g -O0 -pthread \
          -I.. -I$(TEMPLATE_DIR) -I$(SQLITE_DIR) -I.

# Source file paths
SQLITE_C   := $(SQLITE_DIR)/sqlite3.c
CSORMA_C   := $(TEMPLATE_DIR)/csorma.c
CSORMA_H   := $(TEMPLATE_DIR)/csorma.h
LOGGER_C   := $(TEMPLATE_DIR)/logger.c
LOGGER_H   := $(TEMPLATE_DIR)/logger.h

# All test binaries
ALL_BINS := $(BIN_DIR)/test_str_utils \
            $(BIN_DIR)/test_bindvars \
            $(BIN_DIR)/test_db_ops \
            $(BIN_DIR)/test_schema \
            $(BIN_DIR)/test_resultset \
            $(BIN_DIR)/test_threading \
            $(BIN_DIR)/test_sql_clauses \
            $(BIN_DIR)/test_column_lookup \
            $(BIN_DIR)/test_logger \
            $(BIN_DIR)/test_busy \
            $(BIN_DIR)/test_leaks \
            $(BIN_DIR)/test_bind_stmt \
            $(BIN_DIR)/test_error_recovery \
            $(BIN_DIR)/test_bind_lifetime \
            $(BIN_DIR)/test_type_coercion \
            $(BIN_DIR)/test_path_build \
            $(BIN_DIR)/test_str_con_null \
            $(BIN_DIR)/test_unicode

# Phony targets: these are always considered out-of-date
.PHONY: all test_all test_str test_bind test_db test_schema test_resultset \
        test_thread test_clauses test_column test_logger test_busy test_leaks \
        test_bind_stmt test_error test_lifetime test_coercion test_path \
        test_str_con_null test_unicode \
        asan_all tsan_all ubsan_all clean objs build_all

# Default target
all: test_all

# ============================================================
#  Directory creation
# ============================================================
$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

# ============================================================
#  Compile shared objects (done once, reused by all tests)
#
#  These are the REAL source files from ../template/ compiled
#  into object files. Every test binary links against these.
#  When the source changes, make recompiles automatically.
# ============================================================
objs: $(BUILD_DIR) $(BUILD_DIR)/sqlite3.o $(BUILD_DIR)/csorma.o $(BUILD_DIR)/logger.o

# SQLite3 amalgamation — compiled with permissive warnings since
# it's third-party code we don't control.
$(BUILD_DIR)/sqlite3.o: $(SQLITE_C) | $(BUILD_DIR)
	@echo "=== Compiling SQLite3 ==="
	$(CC) -c $(CFLAGS) $(CFLAGS_EXTRA) \
		-DSQLITE_THREADSAFE=1 -DSQLITE_TEMP_STORE=2 \
		-Wno-unused-parameter -Wno-implicit-fallthrough \
		-Wno-pointer-arith -Wno-sign-compare -Wno-double-promotion \
		$(SQLITE_C) -o $@

# The main csorma runtime — this is the code under test.
$(BUILD_DIR)/csorma.o: $(CSORMA_C) $(CSORMA_H) | $(BUILD_DIR)
	@echo "=== Compiling csorma.c ==="
	$(CC) -c $(CFLAGS) $(CFLAGS_EXTRA) $(CSORMA_C) -o $@

# Logger — needed by csorma.c for CSORMA_LOGGER_* macros.
$(BUILD_DIR)/logger.o: $(LOGGER_C) $(LOGGER_H) | $(BUILD_DIR)
	@echo "=== Compiling logger.c ==="
	$(CC) -c $(CFLAGS) $(CFLAGS_EXTRA) $(LOGGER_C) -o $@

# ============================================================
#  Build test binaries
#
#  Each test links against the real csorma.o + logger.o + sqlite3.o.
#  CFLAGS_EXTRA is injected by sanitizer builds (asan_all, etc.)
# ============================================================

# --- String utility tests ---
$(BIN_DIR)/test_str_utils: test_str_utils.c objs | $(BIN_DIR)
	@echo "=== Building test_str_utils ==="
	$(CC) $(CFLAGS) $(CFLAGS_EXTRA) $< \
		$(BUILD_DIR)/csorma.o $(BUILD_DIR)/logger.o $(BUILD_DIR)/sqlite3.o \
		-o $@ -lm -pthread
	@echo "  -> $@"

# --- Bind variable tests ---
$(BIN_DIR)/test_bindvars: test_bindvars.c objs | $(BIN_DIR)
	@echo "=== Building test_bindvars ==="
	$(CC) $(CFLAGS) $(CFLAGS_EXTRA) $< \
		$(BUILD_DIR)/csorma.o $(BUILD_DIR)/logger.o $(BUILD_DIR)/sqlite3.o \
		-o $@ -lm -pthread
	@echo "  -> $@"

# --- Database operation tests ---
$(BIN_DIR)/test_db_ops: test_db_ops.c objs | $(BIN_DIR)
	@echo "=== Building test_db_ops ==="
	$(CC) $(CFLAGS) $(CFLAGS_EXTRA) $< \
		$(BUILD_DIR)/csorma.o $(BUILD_DIR)/logger.o $(BUILD_DIR)/sqlite3.o \
		-o $@ -lm -pthread
	@echo "  -> $@"

# --- Schema upgrade tests ---
$(BIN_DIR)/test_schema: test_schema.c objs | $(BIN_DIR)
	@echo "=== Building test_schema ==="
	$(CC) $(CFLAGS) $(CFLAGS_EXTRA) $< \
		$(BUILD_DIR)/csorma.o $(BUILD_DIR)/logger.o $(BUILD_DIR)/sqlite3.o \
		-o $@ -lm -pthread
	@echo "  -> $@"

# --- Result set tests ---
$(BIN_DIR)/test_resultset: test_resultset.c objs | $(BIN_DIR)
	@echo "=== Building test_resultset ==="
	$(CC) $(CFLAGS) $(CFLAGS_EXTRA) $< \
		$(BUILD_DIR)/csorma.o $(BUILD_DIR)/logger.o $(BUILD_DIR)/sqlite3.o \
		-o $@ -lm -pthread
	@echo "  -> $@"

# --- Threading / concurrency tests ---
$(BIN_DIR)/test_threading: test_threading.c objs | $(BIN_DIR)
	@echo "=== Building test_threading ==="
	$(CC) $(CFLAGS) $(CFLAGS_EXTRA) $< \
		$(BUILD_DIR)/csorma.o $(BUILD_DIR)/logger.o $(BUILD_DIR)/sqlite3.o \
		-o $@ -lm -pthread
	@echo "  -> $@"

# --- SQL clause building tests ---
$(BIN_DIR)/test_sql_clauses: test_sql_clauses.c objs | $(BIN_DIR)
	@echo "=== Building test_sql_clauses ==="
	$(CC) $(CFLAGS) $(CFLAGS_EXTRA) $< \
		$(BUILD_DIR)/csorma.o $(BUILD_DIR)/logger.o $(BUILD_DIR)/sqlite3.o \
		-o $@ -lm -pthread
	@echo "  -> $@"

# --- Column lookup tests (rs_find_column_idx) ---
$(BIN_DIR)/test_column_lookup: test_column_lookup.c objs | $(BIN_DIR)
	@echo "=== Building test_column_lookup ==="
	$(CC) $(CFLAGS) $(CFLAGS_EXTRA) $< \
		$(BUILD_DIR)/csorma.o $(BUILD_DIR)/logger.o $(BUILD_DIR)/sqlite3.o \
		-o $@ -lm -pthread
	@echo "  -> $@"

# --- Logger edge case tests ---
$(BIN_DIR)/test_logger: test_logger.c objs | $(BIN_DIR)
	@echo "=== Building test_logger ==="
	$(CC) $(CFLAGS) $(CFLAGS_EXTRA) $< \
		$(BUILD_DIR)/csorma.o $(BUILD_DIR)/logger.o $(BUILD_DIR)/sqlite3.o \
		-o $@ -lm -pthread
	@echo "  -> $@"

# --- SQLITE_BUSY handling tests ---
$(BIN_DIR)/test_busy: test_busy.c objs | $(BIN_DIR)
	@echo "=== Building test_busy ==="
	$(CC) $(CFLAGS) $(CFLAGS_EXTRA) $< \
		$(BUILD_DIR)/csorma.o $(BUILD_DIR)/logger.o $(BUILD_DIR)/sqlite3.o \
		-o $@ -lm -pthread
	@echo "  -> $@"

# --- Memory leak lifecycle tests ---
$(BIN_DIR)/test_leaks: test_leaks.c objs | $(BIN_DIR)
	@echo "=== Building test_leaks ==="
	$(CC) $(CFLAGS) $(CFLAGS_EXTRA) $< \
		$(BUILD_DIR)/csorma.o $(BUILD_DIR)/logger.o $(BUILD_DIR)/sqlite3.o \
		-o $@ -lm -pthread
	@echo "  -> $@"

# --- Bind-to-stmt tests (sqlite3_bind_* verification) ---
$(BIN_DIR)/test_bind_stmt: test_bind_stmt.c objs | $(BIN_DIR)
	@echo "=== Building test_bind_stmt ==="
	$(CC) $(CFLAGS) $(CFLAGS_EXTRA) $< \
		$(BUILD_DIR)/csorma.o $(BUILD_DIR)/logger.o $(BUILD_DIR)/sqlite3.o \
		-o $@ -lm -pthread
	@echo "  -> $@"

# --- Error recovery tests ---
$(BIN_DIR)/test_error_recovery: test_error_recovery.c objs | $(BIN_DIR)
	@echo "=== Building test_error_recovery ==="
	$(CC) $(CFLAGS) $(CFLAGS_EXTRA) $< \
		$(BUILD_DIR)/csorma.o $(BUILD_DIR)/logger.o $(BUILD_DIR)/sqlite3.o \
		-o $@ -lm -pthread
	@echo "  -> $@"

# --- SQLITE_STATIC binding lifetime tests ---
$(BIN_DIR)/test_bind_lifetime: test_bind_lifetime.c objs | $(BIN_DIR)
	@echo "=== Building test_bind_lifetime ==="
	$(CC) $(CFLAGS) $(CFLAGS_EXTRA) $< \
		$(BUILD_DIR)/csorma.o $(BUILD_DIR)/logger.o $(BUILD_DIR)/sqlite3.o \
		-o $@ -lm -pthread
	@echo "  -> $@"

# --- Type coercion tests ---
$(BIN_DIR)/test_type_coercion: test_type_coercion.c objs | $(BIN_DIR)
	@echo "=== Building test_type_coercion ==="
	$(CC) $(CFLAGS) $(CFLAGS_EXTRA) $< \
		$(BUILD_DIR)/csorma.o $(BUILD_DIR)/logger.o $(BUILD_DIR)/sqlite3.o \
		-o $@ -lm -pthread
	@echo "  -> $@"

# --- Path building tests (str_buf_concat via OrmaDatabase_init) ---
$(BIN_DIR)/test_path_build: test_path_build.c objs | $(BIN_DIR)
	@echo "=== Building test_path_build ==="
	$(CC) $(CFLAGS) $(CFLAGS_EXTRA) $< \
		$(BUILD_DIR)/csorma.o $(BUILD_DIR)/logger.o $(BUILD_DIR)/sqlite3.o \
		-o $@ -lm -pthread
	@echo "  -> $@"

# --- csorma_str_con NULL b1 tests ---
$(BIN_DIR)/test_str_con_null: test_str_con_null.c objs | $(BIN_DIR)
	@echo "=== Building test_str_con_null ==="
	$(CC) $(CFLAGS) $(CFLAGS_EXTRA) $< \
		$(BUILD_DIR)/csorma.o $(BUILD_DIR)/logger.o $(BUILD_DIR)/sqlite3.o \
		-o $@ -lm -pthread
	@echo "  -> $@"

# --- Unicode and special character tests ---
$(BIN_DIR)/test_unicode: test_unicode.c objs | $(BIN_DIR)
	@echo "=== Building test_unicode ==="
	$(CC) $(CFLAGS) $(CFLAGS_EXTRA) $< \
		$(BUILD_DIR)/csorma.o $(BUILD_DIR)/logger.o $(BUILD_DIR)/sqlite3.o \
		-o $@ -lm -pthread
	@echo "  -> $@"

# ============================================================
#  Build ALL binaries
#
#  This target builds every test binary. If ANY compilation
#  fails, make stops immediately with an error. This is used
#  as a prerequisite of test_all so build errors are never
#  silently swallowed.
# ============================================================
build_all: $(ALL_BINS)
	@echo ""
	@echo "=== All 18 test binaries built successfully ==="

# ============================================================
#  Run targets
#
#  Each target builds the binary (if needed) then executes it.
#  The test binary returns 0 on success, 1 on failure.
# ============================================================

test_str: $(BIN_DIR)/test_str_utils
	@echo ""
	@echo "============================================================"
	@echo "  Running: String Utility Tests"
	@echo "============================================================"
	./$(BIN_DIR)/test_str_utils

test_bind: $(BIN_DIR)/test_bindvars
	@echo ""
	@echo "============================================================"
	@echo "  Running: Bind Variable Tests"
	@echo "============================================================"
	./$(BIN_DIR)/test_bindvars

test_db: $(BIN_DIR)/test_db_ops
	@echo ""
	@echo "============================================================"
	@echo "  Running: Database Operation Tests"
	@echo "============================================================"
	./$(BIN_DIR)/test_db_ops

test_schema: $(BIN_DIR)/test_schema
	@echo ""
	@echo "============================================================"
	@echo "  Running: Schema Upgrade Tests"
	@echo "============================================================"
	./$(BIN_DIR)/test_schema

test_resultset: $(BIN_DIR)/test_resultset
	@echo ""
	@echo "============================================================"
	@echo "  Running: Result Set Tests"
	@echo "============================================================"
	./$(BIN_DIR)/test_resultset

test_thread: $(BIN_DIR)/test_threading
	@echo ""
	@echo "============================================================"
	@echo "  Running: Threading / Concurrency Tests"
	@echo "============================================================"
	./$(BIN_DIR)/test_threading

test_clauses: $(BIN_DIR)/test_sql_clauses
	@echo ""
	@echo "============================================================"
	@echo "  Running: SQL Clause Building Tests"
	@echo "============================================================"
	./$(BIN_DIR)/test_sql_clauses

test_column: $(BIN_DIR)/test_column_lookup
	@echo ""
	@echo "============================================================"
	@echo "  Running: Column Lookup Tests"
	@echo "============================================================"
	./$(BIN_DIR)/test_column_lookup

test_logger: $(BIN_DIR)/test_logger
	@echo ""
	@echo "============================================================"
	@echo "  Running: Logger Edge Case Tests"
	@echo "============================================================"
	./$(BIN_DIR)/test_logger

test_busy: $(BIN_DIR)/test_busy
	@echo ""
	@echo "============================================================"
	@echo "  Running: SQLITE_BUSY Handling Tests"
	@echo "============================================================"
	./$(BIN_DIR)/test_busy

test_leaks: $(BIN_DIR)/test_leaks
	@echo ""
	@echo "============================================================"
	@echo "  Running: Memory Leak Lifecycle Tests"
	@echo "============================================================"
	./$(BIN_DIR)/test_leaks

test_bind_stmt: $(BIN_DIR)/test_bind_stmt
	@echo ""
	@echo "============================================================"
	@echo "  Running: Bind-to-Stmt Tests"
	@echo "============================================================"
	./$(BIN_DIR)/test_bind_stmt

test_error: $(BIN_DIR)/test_error_recovery
	@echo ""
	@echo "============================================================"
	@echo "  Running: Error Recovery Tests"
	@echo "============================================================"
	./$(BIN_DIR)/test_error_recovery

test_lifetime: $(BIN_DIR)/test_bind_lifetime
	@echo ""
	@echo "============================================================"
	@echo "  Running: SQLITE_STATIC Binding Lifetime Tests"
	@echo "============================================================"
	./$(BIN_DIR)/test_bind_lifetime

test_coercion: $(BIN_DIR)/test_type_coercion
	@echo ""
	@echo "============================================================"
	@echo "  Running: Type Coercion Tests"
	@echo "============================================================"
	./$(BIN_DIR)/test_type_coercion

test_path: $(BIN_DIR)/test_path_build
	@echo ""
	@echo "============================================================"
	@echo "  Running: Path Building Tests"
	@echo "============================================================"
	./$(BIN_DIR)/test_path_build

test_str_con_null: $(BIN_DIR)/test_str_con_null
	@echo ""
	@echo "============================================================"
	@echo "  Running: csorma_str_con NULL b1 Tests"
	@echo "============================================================"
	./$(BIN_DIR)/test_str_con_null

test_unicode: $(BIN_DIR)/test_unicode
	@echo ""
	@echo "============================================================"
	@echo "  Running: Unicode & Special Character Tests"
	@echo "============================================================"
	./$(BIN_DIR)/test_unicode

# ============================================================
#  Run ALL tests
#
#  PHASE 1 (build_all): Builds every test binary. If ANY
#  compilation or link error occurs, make STOPS immediately.
#  Build errors are never swallowed.
#
#  PHASE 2 (run): Runs every test binary. Test FAILURES
#  (exit code 1) do NOT stop other tests — all suites run
#  and a summary is printed at the end.
#
#  PHASE 3 (aggregate): Parses the per-binary test_summary()
#  output and prints a GRAND TOTAL of individual tests across
#  all suites. Each binary already prints its own summary;
#  this adds a combined total at the very end.
# ============================================================
test_all: build_all
	@echo ""
	@echo "============================================================"
	@echo "  RUNNING ALL TEST SUITES"
	@echo "============================================================"
	@OUTFILE=$$(mktemp); \
	TOTAL_TESTS=0; \
	TOTAL_PASSED=0; \
	TOTAL_FAILED=0; \
	SUITES_RUN=0; \
	SUITES_FAILED=0; \
	for BIN in \
		$(BIN_DIR)/test_str_utils \
		$(BIN_DIR)/test_bindvars \
		$(BIN_DIR)/test_db_ops \
		$(BIN_DIR)/test_schema \
		$(BIN_DIR)/test_resultset \
		$(BIN_DIR)/test_threading \
		$(BIN_DIR)/test_sql_clauses \
		$(BIN_DIR)/test_column_lookup \
		$(BIN_DIR)/test_logger \
		$(BIN_DIR)/test_busy \
		$(BIN_DIR)/test_leaks \
		$(BIN_DIR)/test_bind_stmt \
		$(BIN_DIR)/test_error_recovery \
		$(BIN_DIR)/test_bind_lifetime \
		$(BIN_DIR)/test_type_coercion \
		$(BIN_DIR)/test_path_build \
		$(BIN_DIR)/test_str_con_null \
		$(BIN_DIR)/test_unicode; \
	do \
		./$$BIN > $$OUTFILE 2>&1; \
		RC=$$?; \
		cat $$OUTFILE; \
		SUITES_RUN=$$((SUITES_RUN+1)); \
		if [ $$RC -ne 0 ]; then \
			SUITES_FAILED=$$((SUITES_FAILED+1)); \
		fi; \
		CLEAN=$$(sed "s/$$'\033'\\[[0-9;]*[a-zA-Z]//g" $$OUTFILE); \
		T=$$(echo "$$CLEAN" | grep 'Total:' | tail -n1 | awk '{print $$NF}'); \
		P=$$(echo "$$CLEAN" | grep 'Passed:' | tail -n1 | awk '{print $$NF}'); \
		F=$$(echo "$$CLEAN" | grep 'Failed:' | tail -n1 | awk '{print $$NF}'); \
		T=$${T:-0}; P=$${P:-0}; F=$${F:-0}; \
		TOTAL_TESTS=$$((TOTAL_TESTS + T)); \
		TOTAL_PASSED=$$((TOTAL_PASSED + P)); \
		TOTAL_FAILED=$$((TOTAL_FAILED + F)); \
	done; \
	rm -f $$OUTFILE; \
	echo ""; \
	echo "============================================================"; \
	echo "  GRAND TOTAL (all individual tests across all suites)"; \
	echo "============================================================"; \
	echo "    Total:   $$TOTAL_TESTS"; \
	echo "    Passed:  $$TOTAL_PASSED"; \
	echo "    Failed:  $$TOTAL_FAILED"; \
	echo "    Suites:  $$SUITES_RUN run, $$SUITES_FAILED with failures"; \
	echo "============================================================"; \
	if [ $$TOTAL_FAILED -eq 0 ]; then \
		echo "    >>> ALL $$TOTAL_TESTS TESTS PASSED <<<"; \
	else \
		echo "    >>> $$TOTAL_FAILED TEST(S) FAILED <<<"; \
	fi; \
	echo "============================================================"; \
	echo ""; \
	exit $$TOTAL_FAILED

# ============================================================
#  Sanitized builds
#
#  These clean first, then rebuild everything with sanitizer
#  flags injected via CFLAGS_EXTRA. This ensures all .o files
#  and test binaries are compiled with instrumentation.
#
#  ASAN:  catches heap-buffer-overflow, use-after-free, leaks
#  TSAN:  catches data races (critical for threading tests)
#  UBSAN: catches signed overflow, null deref, misalignment
# ============================================================
asan_all: clean
	@echo "=== ASAN BUILD ==="
	$(MAKE) CFLAGS_EXTRA="-fsanitize=address -fno-omit-frame-pointer" test_all

tsan_all: clean
	@echo "=== TSAN BUILD ==="
	$(MAKE) CFLAGS_EXTRA="-fsanitize=thread -fno-omit-frame-pointer" test_all

ubsan_all: clean
	@echo "=== UBSAN BUILD ==="
	$(MAKE) CFLAGS_EXTRA="-fsanitize=undefined,float-divide-by-zero -fno-sanitize-recover=all" test_all

# ============================================================
#  Clean
#
#  Removes all generated files: object files, test binaries,
#  and any leftover database files from test runs.
# ============================================================
clean:
	rm -rf $(BUILD_DIR) $(BIN_DIR)
	rm -f *.db *.db-journal *.db-wal *.db-shm
	rm -f /tmp/_csorma_busy_test.db*
	rm -f ':memory:ignored.db'
	@echo "Cleaned."
