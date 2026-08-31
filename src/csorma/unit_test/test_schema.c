/*
 * test_schema.c — Tests for schema upgrade functions
 */
#include "test_framework.h"
#include "csorma.h"

static uint32_t _calls[100][2];
static int _count = 0;

static void _cb(uint32_t old_v, uint32_t new_v) {
    if (_count < 100) { _calls[_count][0] = old_v; _calls[_count][1] = new_v; }
    _count++;
}

static bool t_schema_fresh(void) {
    _count = 0;
    OrmaDatabase *o = OrmaDatabase_init((const uint8_t*)":memory:", 8, (const uint8_t*)"", 0);
    OrmaDatabase_set_schema_upgrade_callback(_cb);
    OrmaDatabase_do_schema_upgrade(o, 1);
    T_ASSERT_INT_EQ(_count, 1, "one call");
    T_ASSERT_INT_EQ(_calls[0][0], 0, "from 0");
    T_ASSERT_INT_EQ(_calls[0][1], 1, "to 1");
    OrmaDatabase_shutdown(o);
    return true;
}

static bool t_schema_multi(void) {
    _count = 0;
    OrmaDatabase *o = OrmaDatabase_init((const uint8_t*)":memory:", 8, (const uint8_t*)"", 0);
    OrmaDatabase_set_schema_upgrade_callback(_cb);
    OrmaDatabase_do_schema_upgrade(o, 5);
    T_ASSERT_INT_EQ(_count, 5, "five calls");
    for (int i = 0; i < 5; i++) {
        T_ASSERT_INT_EQ(_calls[i][0], i, "from");
        T_ASSERT_INT_EQ(_calls[i][1], i+1, "to");
    }
    OrmaDatabase_shutdown(o);
    return true;
}

static bool t_schema_no_upgrade(void) {
    _count = 0;
    OrmaDatabase *o = OrmaDatabase_init((const uint8_t*)":memory:", 8, (const uint8_t*)"", 0);
    OrmaDatabase_set_schema_upgrade_callback(_cb);
    OrmaDatabase_do_schema_upgrade(o, 1);
    _count = 0;
    OrmaDatabase_do_schema_upgrade(o, 1);
    T_ASSERT_INT_EQ(_count, 0, "no calls on same version");
    OrmaDatabase_shutdown(o);
    return true;
}

static bool t_schema_null_cb(void) {
    OrmaDatabase *o = OrmaDatabase_init((const uint8_t*)":memory:", 8, (const uint8_t*)"", 0);
    OrmaDatabase_set_schema_upgrade_callback(NULL);
    OrmaDatabase_do_schema_upgrade(o, 3);
    OrmaDatabase_shutdown(o);
    return true;
}

int main(void) {
    printf(C_BOLD "\n  CSORMA SCHEMA UPGRADE TESTS\n" C_RESET "\n");

    TEST_SUITE("Schema upgrade");
    RUN_TEST(t_schema_fresh);
    RUN_TEST(t_schema_multi);
    RUN_TEST(t_schema_no_upgrade);
    RUN_TEST(t_schema_null_cb);
    SUITE_END();

    return test_summary("Schema Upgrade");
}
