/*
 * test_bindvars.c — Tests for bindvar_* functions
 * Links against the REAL ../template/csorma.c
 */
#include "test_framework.h"
#include "csorma.h"

static bool t_bindvar_init_null(void) {
    OrmaBindvars *bv = bindvar_init(NULL);
    T_ASSERT_PTR_NOT_NULL(bv, "creates new");
    T_ASSERT_INT_EQ(bv->items, 0, "empty");
    bindvar_free(bv);
    return true;
}

static bool t_bindvar_add_int(void) {
    OrmaBindvars *bv = bindvar_init(NULL);
    bv = bindvar_add_n(bv, 42, BINDVAR_TYPE_Int);
    T_ASSERT_INT_EQ(bv->items, 1, "one item");
    T_ASSERT_INT_EQ(bv->b[0].n, 42, "value");
    T_ASSERT_INT_EQ(bv->b[0].t, BINDVAR_TYPE_Int, "type");
    bindvar_free(bv);
    return true;
}

static bool t_bindvar_add_long(void) {
    OrmaBindvars *bv = bindvar_init(NULL);
    bv = bindvar_add_n(bv, 9999999999LL, BINDVAR_TYPE_Long);
    T_ASSERT_INT_EQ(bv->b[0].n, 9999999999LL, "value");
    T_ASSERT_INT_EQ(bv->b[0].t, BINDVAR_TYPE_Long, "type");
    bindvar_free(bv);
    return true;
}

static bool t_bindvar_add_bool(void) {
    OrmaBindvars *bv = bindvar_init(NULL);
    bv = bindvar_add_n(bv, 1, BINDVAR_TYPE_Boolean);
    bv = bindvar_add_n(bv, 0, BINDVAR_TYPE_Boolean);
    T_ASSERT_INT_EQ(bv->items, 2, "two items");
    T_ASSERT_INT_EQ(bv->b[0].n, 1, "true");
    T_ASSERT_INT_EQ(bv->b[1].n, 0, "false");
    bindvar_free(bv);
    return true;
}

static bool t_bindvar_add_string(void) {
    OrmaBindvars *bv = bindvar_init(NULL);
    csorma_s *str = csorma_str2_build("hello");
    bv = bindvar_add_s(bv, str);
    T_ASSERT_INT_EQ(bv->items, 1, "one item");
    T_ASSERT_INT_EQ(bv->b[0].t, BINDVAR_TYPE_String, "type");
    T_ASSERT_PTR_EQ(bv->b[0].s, str, "pointer preserved");
    bindvar_free(bv);
    return true;
}

static bool t_bindvar_add_many(void) {
    OrmaBindvars *bv = bindvar_init(NULL);
    for (int i = 0; i < 100; i++)
        bv = bindvar_add_n(bv, i, BINDVAR_TYPE_Int);
    T_ASSERT_INT_EQ(bv->items, 100, "100 items");
    for (int i = 0; i < 100; i++)
        T_ASSERT_INT_EQ(bv->b[i].n, i, "value check");
    bindvar_free(bv);
    return true;
}

static bool t_bindvar_mixed(void) {
    OrmaBindvars *bv = bindvar_init(NULL);
    bv = bindvar_add_n(bv, 1, BINDVAR_TYPE_Int);
    csorma_s *s = csorma_str2_build("test");
    bv = bindvar_add_s(bv, s);
    bv = bindvar_add_n(bv, 999, BINDVAR_TYPE_Long);
    T_ASSERT_INT_EQ(bv->items, 3, "3 items");
    T_ASSERT_INT_EQ(bv->b[0].t, BINDVAR_TYPE_Int, "type 0");
    T_ASSERT_INT_EQ(bv->b[1].t, BINDVAR_TYPE_String, "type 1");
    T_ASSERT_INT_EQ(bv->b[2].t, BINDVAR_TYPE_Long, "type 2");
    bindvar_free(bv);
    return true;
}

static bool t_bindvar_free_null(void) {
    bindvar_free(NULL);
    return true;
}

static bool t_bindvar_add_to_null(void) {
    OrmaBindvars *bv = NULL;
    bv = bindvar_add_n(bv, 77, BINDVAR_TYPE_Int);
    T_ASSERT_PTR_NOT_NULL(bv, "creates from NULL");
    T_ASSERT_INT_EQ(bv->b[0].n, 77, "value");
    bindvar_free(bv);
    return true;
}

static bool t_bindvar_add_string_null(void) {
    OrmaBindvars *bv = bindvar_init(NULL);
    bv = bindvar_add_s(bv, NULL);
    T_ASSERT_INT_EQ(bv->items, 1, "one item");
    T_ASSERT_INT_EQ(bv->b[0].t, BINDVAR_TYPE_String, "type");
    T_ASSERT_PTR_NULL(bv->b[0].s, "NULL string");
    bindvar_free(bv);
    return true;
}

int main(void) {
    printf(C_BOLD "\n");
    printf("  ================================================================\n");
    printf("   CSORMA BIND VARIABLE UNIT TESTS\n");
    printf("   Source: ../template/csorma.c (compiled directly)\n");
    printf("  ================================================================\n");
    printf(C_RESET "\n");

    TEST_SUITE("bindvar_init");
    RUN_TEST(t_bindvar_init_null);
    SUITE_END();

    TEST_SUITE("bindvar_add_n");
    RUN_TEST(t_bindvar_add_int);
    RUN_TEST(t_bindvar_add_long);
    RUN_TEST(t_bindvar_add_bool);
    RUN_TEST(t_bindvar_add_many);
    RUN_TEST(t_bindvar_add_to_null);
    SUITE_END();

    TEST_SUITE("bindvar_add_s");
    RUN_TEST(t_bindvar_add_string);
    RUN_TEST(t_bindvar_add_string_null);
    SUITE_END();

    TEST_SUITE("bindvar mixed");
    RUN_TEST(t_bindvar_mixed);
    SUITE_END();

    TEST_SUITE("bindvar_free");
    RUN_TEST(t_bindvar_free_null);
    SUITE_END();

    return test_summary("Bind Variables");
}
