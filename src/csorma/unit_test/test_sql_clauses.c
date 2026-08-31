/*
 * test_sql_clauses.c — Tests for SQL clause building functions
 *
 * Tests:
 *   - bind_to_where_sql_int()
 *   - bind_to_where_sql_string()
 *   - bind_to_set_sql_int()
 *   - bind_to_set_sql_string()
 *   - add_to_where_sql_string()
 *   - add_to_orderby_asc_sql()
 *
 * These functions construct WHERE, SET, and ORDER BY fragments
 * with bind-variable placeholders (?400, ?401, ?600, ?601...)
 */

#include "test_framework.h"
#include "csorma.h"

/* ============================================================
 *  bind_to_where_sql_int() tests
 * ============================================================ */

static bool t_where_int_single(void)
{
    csorma_s *sql = csorma_str2_build(" WHERE 1=1 ");
    OrmaBindvars *bv = bindvar_init(NULL);

    bind_to_where_sql_int(sql, bv, " AND \"age\" = ?", 25, BINDVAR_TYPE_Int, " ");

    /* Verify SQL contains the placeholder */
    T_ASSERT(sql->l > 0, "sql not empty");
    T_ASSERT(strstr((const char*)sql->s, "AND \"age\" = ?") != NULL,
             "contains column clause");

    /* Verify bindvar was added */
    T_ASSERT_INT_EQ(bv->items, 1, "one bindvar added");
    T_ASSERT_INT_EQ(bv->b[0].n, 25, "value=25");
    T_ASSERT_INT_EQ(bv->b[0].t, BINDVAR_TYPE_Int, "type=Int");

    csorma_str_free(sql);
    bindvar_free(bv);
    return true;
}

static bool t_where_int_multiple(void)
{
    csorma_s *sql = csorma_str2_build(" WHERE 1=1 ");
    OrmaBindvars *bv = bindvar_init(NULL);

    bind_to_where_sql_int(sql, bv, " AND \"age\" = ?", 25, BINDVAR_TYPE_Int, " ");
    bind_to_where_sql_int(sql, bv, " AND \"score\" > ?", 100, BINDVAR_TYPE_Int, " ");
    bind_to_where_sql_int(sql, bv, " AND \"id\" = ?", 999, BINDVAR_TYPE_Long, " ");

    T_ASSERT_INT_EQ(bv->items, 3, "three bindvars");
    T_ASSERT_INT_EQ(bv->b[0].n, 25, "first=25");
    T_ASSERT_INT_EQ(bv->b[1].n, 100, "second=100");
    T_ASSERT_INT_EQ(bv->b[2].n, 999, "third=999");
    T_ASSERT_INT_EQ(bv->b[2].t, BINDVAR_TYPE_Long, "third is Long");

    csorma_str_free(sql);
    bindvar_free(bv);
    return true;
}

static bool t_where_int_boolean(void)
{
    csorma_s *sql = csorma_str2_build(" WHERE 1=1 ");
    OrmaBindvars *bv = bindvar_init(NULL);

    bind_to_where_sql_int(sql, bv, " AND \"active\" = ?", 1, BINDVAR_TYPE_Boolean, " ");

    T_ASSERT_INT_EQ(bv->items, 1, "one bindvar");
    T_ASSERT_INT_EQ(bv->b[0].t, BINDVAR_TYPE_Boolean, "type=Boolean");
    T_ASSERT_INT_EQ(bv->b[0].n, 1, "value=1 (true)");

    csorma_str_free(sql);
    bindvar_free(bv);
    return true;
}

static bool t_where_int_negative(void)
{
    csorma_s *sql = csorma_str2_build(" WHERE 1=1 ");
    OrmaBindvars *bv = bindvar_init(NULL);

    bind_to_where_sql_int(sql, bv, " AND \"temp\" > ?", -40, BINDVAR_TYPE_Int, " ");

    T_ASSERT_INT_EQ(bv->b[0].n, -40, "negative value");

    csorma_str_free(sql);
    bindvar_free(bv);
    return true;
}

static bool t_where_int_large(void)
{
    csorma_s *sql = csorma_str2_build(" WHERE 1=1 ");
    OrmaBindvars *bv = bindvar_init(NULL);

    bind_to_where_sql_int(sql, bv, " AND \"bignum\" = ?", 9223372036854775807LL,
                          BINDVAR_TYPE_Long, " ");

    T_ASSERT_INT_EQ(bv->b[0].n, 9223372036854775807LL, "INT64_MAX");

    csorma_str_free(sql);
    bindvar_free(bv);
    return true;
}

/* ============================================================
 *  bind_to_where_sql_string() tests
 * ============================================================ */

static bool t_where_string_basic(void)
{
    csorma_s *sql = csorma_str2_build(" WHERE 1=1 ");
    OrmaBindvars *bv = bindvar_init(NULL);
    csorma_s *val = csorma_str2_build("hello");

    bind_to_where_sql_string(sql, bv, " AND \"name\" = ?", val, BINDVAR_TYPE_String, " ");

    T_ASSERT_INT_EQ(bv->items, 1, "one bindvar");
    T_ASSERT_INT_EQ(bv->b[0].t, BINDVAR_TYPE_String, "type=String");
    T_ASSERT_PTR_EQ(bv->b[0].s, val, "pointer preserved");

    csorma_str_free(sql);
    bindvar_free(bv);
    return true;
}

static bool t_where_string_null(void)
{
    csorma_s *sql = csorma_str2_build(" WHERE 1=1 ");
    OrmaBindvars *bv = bindvar_init(NULL);

    bind_to_where_sql_string(sql, bv, " AND \"name\" = ?", NULL, BINDVAR_TYPE_String, " ");

    T_ASSERT_INT_EQ(bv->items, 1, "one bindvar");
    T_ASSERT_PTR_NULL(bv->b[0].s, "NULL string stored");

    csorma_str_free(sql);
    bindvar_free(bv);
    return true;
}

static bool t_where_string_empty(void)
{
    csorma_s *sql = csorma_str2_build(" WHERE 1=1 ");
    OrmaBindvars *bv = bindvar_init(NULL);
    csorma_s *val = csorma_str2_build("");

    bind_to_where_sql_string(sql, bv, " AND \"name\" = ?", val, BINDVAR_TYPE_String, " ");

    T_ASSERT_INT_EQ(bv->b[0].s->l, 0, "empty string");

    csorma_str_free(sql);
    bindvar_free(bv);
    return true;
}

static bool t_where_string_binary(void)
{
    csorma_s *sql = csorma_str2_build(" WHERE 1=1 ");
    OrmaBindvars *bv = bindvar_init(NULL);
    const char bin[] = {'\x00', '\xFF', '\x01'};
    csorma_s *val = csorma_str_build(bin, 3);

    bind_to_where_sql_string(sql, bv, " AND \"data\" = ?", val, BINDVAR_TYPE_String, " ");

    T_ASSERT_INT_EQ(bv->b[0].s->l, 3, "binary length");
    T_ASSERT_MEM_EQ(bv->b[0].s->s, bin, 3, "binary content");

    csorma_str_free(sql);
    bindvar_free(bv);
    return true;
}

/* ============================================================
 *  bind_to_set_sql_int() tests
 * ============================================================ */

static bool t_set_int_basic(void)
{
    csorma_s *sql = csorma_str2_build("");
    OrmaBindvars *bv = bindvar_init(NULL);

    bind_to_set_sql_int(sql, bv, "\"age\" = ?", 30, BINDVAR_TYPE_Int);

    T_ASSERT(sql->l > 0, "sql not empty");
    T_ASSERT_INT_EQ(bv->items, 1, "one bindvar");
    T_ASSERT_INT_EQ(bv->b[0].n, 30, "value=30");

    csorma_str_free(sql);
    bindvar_free(bv);
    return true;
}

static bool t_set_int_multiple(void)
{
    csorma_s *sql = csorma_str2_build("");
    OrmaBindvars *bv = bindvar_init(NULL);

    bind_to_set_sql_int(sql, bv, "\"age\" = ?", 30, BINDVAR_TYPE_Int);
    bind_to_set_sql_int(sql, bv, ", \"score\" = ?", 100, BINDVAR_TYPE_Int);
    bind_to_set_sql_int(sql, bv, ", \"active\" = ?", 1, BINDVAR_TYPE_Boolean);

    T_ASSERT_INT_EQ(bv->items, 3, "three bindvars");
    T_ASSERT_INT_EQ(bv->b[0].n, 30, "first");
    T_ASSERT_INT_EQ(bv->b[1].n, 100, "second");
    T_ASSERT_INT_EQ(bv->b[2].n, 1, "third");

    csorma_str_free(sql);
    bindvar_free(bv);
    return true;
}

/* ============================================================
 *  bind_to_set_sql_string() tests
 * ============================================================ */

static bool t_set_string_basic(void)
{
    csorma_s *sql = csorma_str2_build("");
    OrmaBindvars *bv = bindvar_init(NULL);
    csorma_s *val = csorma_str2_build("new_name");

    bind_to_set_sql_string(sql, bv, "\"name\" = ?", val, BINDVAR_TYPE_String);

    T_ASSERT_INT_EQ(bv->items, 1, "one bindvar");
    T_ASSERT_INT_EQ(bv->b[0].t, BINDVAR_TYPE_String, "type");
    T_ASSERT_PTR_EQ(bv->b[0].s, val, "pointer");

    csorma_str_free(sql);
    bindvar_free(bv);
    return true;
}

static bool t_set_string_null(void)
{
    csorma_s *sql = csorma_str2_build("");
    OrmaBindvars *bv = bindvar_init(NULL);

    bind_to_set_sql_string(sql, bv, "\"name\" = ?", NULL, BINDVAR_TYPE_String);

    T_ASSERT_INT_EQ(bv->items, 1, "one bindvar");
    T_ASSERT_PTR_NULL(bv->b[0].s, "NULL stored");

    csorma_str_free(sql);
    bindvar_free(bv);
    return true;
}

/* ============================================================
 *  add_to_where_sql_string() tests
 * ============================================================ */

static bool t_add_where_string(void)
{
    csorma_s *sql = csorma_str2_build(" WHERE 1=1 ");
    add_to_where_sql_string(sql, " AND \"deleted\" = 0 ");

    T_ASSERT(strstr((const char*)sql->s, "AND \"deleted\" = 0") != NULL,
             "raw text appended");

    csorma_str_free(sql);
    return true;
}

static bool t_add_where_string_empty(void)
{
    csorma_s *sql = csorma_str2_build(" WHERE 1=1 ");
    uint32_t before = sql->l;
    add_to_where_sql_string(sql, "");
    T_ASSERT_INT_EQ(sql->l, before, "empty append no change");

    csorma_str_free(sql);
    return true;
}

/* ============================================================
 *  add_to_orderby_asc_sql() tests
 * ============================================================ */

static bool t_orderby_first_asc(void)
{
    csorma_s *sql = csorma_str2_build("");
    add_to_orderby_asc_sql(sql, "\"name\"", true);

    T_ASSERT(strstr((const char*)sql->s, "order by") != NULL, "has 'order by'");
    T_ASSERT(strstr((const char*)sql->s, "\"name\"") != NULL, "has column");
    T_ASSERT(strstr((const char*)sql->s, "ASC") != NULL, "has ASC");

    csorma_str_free(sql);
    return true;
}

static bool t_orderby_first_desc(void)
{
    csorma_s *sql = csorma_str2_build("");
    add_to_orderby_asc_sql(sql, "\"id\"", false);

    T_ASSERT(strstr((const char*)sql->s, "DESC") != NULL, "has DESC");

    csorma_str_free(sql);
    return true;
}

static bool t_orderby_multiple(void)
{
    csorma_s *sql = csorma_str2_build("");
    add_to_orderby_asc_sql(sql, "\"name\"", true);
    add_to_orderby_asc_sql(sql, "\"id\"", false);

    /* Second call should add " , " separator */
    T_ASSERT(strstr((const char*)sql->s, ",") != NULL, "has comma separator");
    T_ASSERT(strstr((const char*)sql->s, "\"name\"") != NULL, "first col");
    T_ASSERT(strstr((const char*)sql->s, "\"id\"") != NULL, "second col");

    csorma_str_free(sql);
    return true;
}

static bool t_orderby_null_sql(void)
{
    csorma_s *sql = NULL;
    sql = csorma_str_con(sql, "", 0); /* create empty */
    add_to_orderby_asc_sql(sql, "\"x\"", true);
    T_ASSERT_PTR_NOT_NULL(sql, "works on empty");
    csorma_str_free(sql);
    return true;
}

/* ============================================================
 *  Bind variable numbering verification
 * ============================================================ */

static bool t_where_bindvar_numbering(void)
{
    /* Verify that WHERE bindvars use offset 400 */
    csorma_s *sql = csorma_str2_build(" WHERE 1=1 ");
    OrmaBindvars *bv = bindvar_init(NULL);

    bind_to_where_sql_int(sql, bv, " AND \"a\" = ?", 1, BINDVAR_TYPE_Int, " ");
    bind_to_where_sql_int(sql, bv, " AND \"b\" = ?", 2, BINDVAR_TYPE_Int, " ");
    bind_to_where_sql_int(sql, bv, " AND \"c\" = ?", 3, BINDVAR_TYPE_Int, " ");

    /* The SQL should contain ?400, ?401, ?402 */
    T_ASSERT(strstr((const char*)sql->s, "400") != NULL, "has ?400");
    T_ASSERT(strstr((const char*)sql->s, "401") != NULL, "has ?401");
    T_ASSERT(strstr((const char*)sql->s, "402") != NULL, "has ?402");

    csorma_str_free(sql);
    bindvar_free(bv);
    return true;
}

static bool t_set_bindvar_numbering(void)
{
    /* Verify that SET bindvars use offset 600 */
    csorma_s *sql = csorma_str2_build("");
    OrmaBindvars *bv = bindvar_init(NULL);

    bind_to_set_sql_int(sql, bv, "\"a\" = ?", 1, BINDVAR_TYPE_Int);
    bind_to_set_sql_int(sql, bv, ", \"b\" = ?", 2, BINDVAR_TYPE_Int);

    T_ASSERT(strstr((const char*)sql->s, "600") != NULL, "has ?600");
    T_ASSERT(strstr((const char*)sql->s, "601") != NULL, "has ?601");

    csorma_str_free(sql);
    bindvar_free(bv);
    return true;
}

/* ============================================================
 *  MAIN
 * ============================================================ */
int main(void)
{
    printf(C_BOLD "\n");
    printf("  ================================================================\n");
    printf("   CSORMA SQL CLAUSE BUILDING TESTS\n");
    printf("   Source: ../template/csorma.c (compiled directly)\n");
    printf("  ================================================================\n");
    printf(C_RESET "\n");

    TEST_SUITE("bind_to_where_sql_int");
    RUN_TEST(t_where_int_single);
    RUN_TEST(t_where_int_multiple);
    RUN_TEST(t_where_int_boolean);
    RUN_TEST(t_where_int_negative);
    RUN_TEST(t_where_int_large);
    SUITE_END();

    TEST_SUITE("bind_to_where_sql_string");
    RUN_TEST(t_where_string_basic);
    RUN_TEST(t_where_string_null);
    RUN_TEST(t_where_string_empty);
    RUN_TEST(t_where_string_binary);
    SUITE_END();

    TEST_SUITE("bind_to_set_sql_int");
    RUN_TEST(t_set_int_basic);
    RUN_TEST(t_set_int_multiple);
    SUITE_END();

    TEST_SUITE("bind_to_set_sql_string");
    RUN_TEST(t_set_string_basic);
    RUN_TEST(t_set_string_null);
    SUITE_END();

    TEST_SUITE("add_to_where_sql_string");
    RUN_TEST(t_add_where_string);
    RUN_TEST(t_add_where_string_empty);
    SUITE_END();

    TEST_SUITE("add_to_orderby_asc_sql");
    RUN_TEST(t_orderby_first_asc);
    RUN_TEST(t_orderby_first_desc);
    RUN_TEST(t_orderby_multiple);
    RUN_TEST(t_orderby_null_sql);
    SUITE_END();

    TEST_SUITE("Bind variable numbering");
    RUN_TEST(t_where_bindvar_numbering);
    RUN_TEST(t_set_bindvar_numbering);
    SUITE_END();

    return test_summary("SQL Clause Building");
}

