
#ifdef ENCRYPT_CSORMA
# include "sqlcipher/sqlite3.h"
#else
# include "sqlite/sqlite3.h"
#endif
#include "csorma.h"
#include "logger.h"

#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef UNUSED
#elif defined(__GNUC__)
# define UNUSED(x) UNUSED_ ## x __attribute__((unused))
#elif defined(__LCLINT__)
# define UNUSED(x) /*@unused@*/ x
#else
# define UNUSED(x) x
#endif

pthread_mutex_t __sorma_global_last_inserted_rowid___mutex;
const char* BINDVAR_TYPE_NAME[] = { "Int", "Long", "String", "Boolean" };

csorma_s *csorma_str2_build(const char *b1)
{
    if (b1 == NULL)
    {
        return NULL;
    }
    const uint32_t b1_len = strlen(b1);
    csorma_s *out = calloc(1, sizeof(csorma_s));
    out->s = calloc(1, b1_len + 1);
    if (out == NULL)
    {
        return NULL;
    }

    CSORMA_LOGGER_DEBUG("001:%d %p", b1_len, b1);
    memcpy(out->s, b1, b1_len);
    out->l = b1_len;
    out->cur = out->s + b1_len;
    out->n = 1;
    return out;
}

csorma_s *csorma_str_build(const char *b1, const uint32_t b1_len)
{
    csorma_s *out = calloc(1, sizeof(csorma_s));
    out->s = calloc(1, b1_len + 1);
    if (out == NULL)
    {
        return NULL;
    }
    CSORMA_LOGGER_DEBUG("002:%d %p", b1_len, b1);
    memcpy(out->s, b1, b1_len);
    // HINT: set the length (this is without NULL terminator)
    out->l = b1_len;
    // HINT: set the new "current" end position
    out->cur = out->s + b1_len;
    // HINT: we have a NULL terminator at the end of the new string
    out->n = 1;
    return out;
}

csorma_s *csorma_str_con2(csorma_s *out, csorma_s *append)
{
    if (append == NULL)
    {
        return out;
    }

    if (out == NULL)
    {
        out = calloc(1, sizeof(csorma_s));
    }

    return csorma_str_con(out, (const char *)append->s, append->l);
}

csorma_s *csorma_str_con_space(csorma_s *out)
{
    return csorma_str_con(out, (const char *)" ", 1);
}

csorma_s *csorma_str_int32t(csorma_s *out, const int32_t append_i)
{
    // HINT: INT32_MAX = 2147483647
    //       INT32_MIN = (-2147483647 - 1)
    //       so we need at least 11 chars for text representation
    //       we use 15 just in case
    const int max_int32_char_len = 15;
    char s[max_int32_char_len + 1];
    // clear 's' with NULL bytes
    memset(s, 0, (max_int32_char_len + 1));
    snprintf(s, max_int32_char_len, "%d", append_i);
    csorma_s *result = csorma_str_con(out, (const char *)s, strlen(s));
    return result;
}

csorma_s *csorma_str_con(csorma_s *out, const char *b1, const uint32_t b1_len)
{
    if (out == NULL)
    {
        out = calloc(1, sizeof(csorma_s));
    }

    out->s = realloc(out->s, out->l + b1_len + 1);
    if (out->s == NULL)
    {
        // HINT: what to do here?? FIX ME
        CSORMA_LOGGER_ERROR("!! PANIC !!");
    }
    // HINT: set the "current" end position
    out->cur = out->s + out->l;
    // HINT: zero out the new region of the buffer including the zero byte at the end
    memset(out->cur, 0, b1_len + 1);
    CSORMA_LOGGER_DEBUG("%d %p", b1_len, b1);
    // HINT: add the new string `b1` at the end
    memcpy(out->cur, b1, b1_len);
    // HINT: set the new length (this is without NULL terminator)
    out->l = out->l + b1_len;
    // HINT: set the new "current" end position
    out->cur = out->cur + out->l;
    // HINT: we have a NULL terminator at the end of the new string
    out->n = 1;
    return out;
}

void csorma_str_free(csorma_s *s)
{
    if (s == NULL)
    {
        return;
    }
    free(s->s);
    free(s);
}

void bindvar_dump(OrmaBindvars *b, int32_t offset)
{
    if (b == NULL)
    {
        CSORMA_LOGGER_ERROR("bindvar: empty");
    }

    if (b->items == 0)
    {
        CSORMA_LOGGER_ERROR("bindvar: has zero items");
    }

    CSORMA_LOGGER_ALWAYS("bindvar: count=%d", b->items);
    /*
    unsigned char *x = (unsigned char *)b->b;
    int size = (sizeof(OrmaBindvar) * b->items);
    printf("bytes=%d\n", size);
    for (int i = 0; i < size; i++)
    {
        printf("%02X ", *x);
        x = x + 1;
    }
    printf("\n");
    */

    OrmaBindvar *b_cur = b->b;
    for (int i=0;i<b->items;i++)
    {
        if (b_cur->s == NULL)
        {
            CSORMA_LOGGER_ALWAYS("bindvar: ?%d(number)=%ld", i+offset, b_cur->n);
        }
        else
        {
            CSORMA_LOGGER_ALWAYS("bindvar: ?%d(string)=%s", i+offset, b_cur->s->s);
        }
        b_cur++;
    }
}

OrmaBindvars *bindvar_init(OrmaBindvars *b)
{
    if (b == NULL)
    {
        b = calloc(1, sizeof(OrmaBindvars));
        b->items = 0;
        b->b = NULL;
    }
    return b;
}

void bindvar_free(OrmaBindvars *b)
{
    if (b == NULL)
    {
        return;
    }

    if (b->items == 0)
    {
        free(b);
        return;
    }

    OrmaBindvar *b_cur = b->b;
    for (int i=0;i<b->items;i++)
    {
        if (b_cur->t == BINDVAR_TYPE_String)
        {
            csorma_str_free(b_cur->s);
        }
        b_cur++;
    }
    free(b->b);
    free(b);
}

OrmaBindvars *bindvar_add_s(OrmaBindvars *b, csorma_s *s)
{
    if (b == NULL)
    {
        b = calloc(1, sizeof(OrmaBindvars));
        b->items = 0;
        b->b = NULL;
    }

    int size = sizeof(OrmaBindvar) * (b->items + 1);
    b->b = realloc(b->b, size);
    OrmaBindvar *tmp = b->b;
    if (b->items > 0)
    {
        tmp = tmp + b->items;
        memset(tmp, 0, sizeof(OrmaBindvar));
    }
    tmp->n = 0;
    tmp->s = NULL;

    // HINT: add the csorma string here
    tmp->s = s;
    tmp->t = BINDVAR_TYPE_String;

    b->items++;

    return b;
}

OrmaBindvars *bindvar_add_n(OrmaBindvars *b, int64_t n, const BINDVAR_TYPE t)
{
    if (b == NULL)
    {
        b = calloc(1, sizeof(OrmaBindvars));
        b->items = 0;
        b->b = NULL;
    }

    int size = sizeof(OrmaBindvar) * (b->items + 1);
    b->b = realloc(b->b, size);
    OrmaBindvar *tmp = b->b;
    if (b->items > 0)
    {
        tmp = tmp + b->items;
        memset(tmp, 0, sizeof(OrmaBindvar));
    }
    tmp->n = 0;
    tmp->s = NULL;

    // HINT: add the number here
    tmp->n = n;
    tmp->t = t;

    b->items++;

    return b;
}

void bindvar_to_stmt(sqlite3_stmt *stmt, int32_t bindvar_idx, const BINDVAR_TYPE bt,
        const int32_t int_value, const int64_t int64_value, const csorma_s *str_value)
{
    if (bt == BINDVAR_TYPE_Long)
    {
        sqlite3_bind_int64(stmt, bindvar_idx, int64_value);
        if (CSORMA_TRACE) { CSORMA_LOGGER_ALWAYS("binding(type:%s) %d=%ld", BINDVAR_TYPE_NAME[bt], bindvar_idx, int64_value); }
    }
    else if (bt == BINDVAR_TYPE_Int)
    {
        sqlite3_bind_int(stmt, bindvar_idx, int_value);
        if (CSORMA_TRACE) { CSORMA_LOGGER_ALWAYS("binding(type:%s) %d=%d", BINDVAR_TYPE_NAME[bt], bindvar_idx, int_value); }
    }
    else if (bt == BINDVAR_TYPE_Boolean)
    {
        sqlite3_bind_int(stmt, bindvar_idx, (bool)int_value);
        if (CSORMA_TRACE) { CSORMA_LOGGER_ALWAYS("binding(type:%s) %d=%d", BINDVAR_TYPE_NAME[bt], bindvar_idx, (bool)int_value); }
    }
    else if (bt == BINDVAR_TYPE_String)
    {
        if (str_value == NULL) {
            sqlite3_bind_text(stmt, bindvar_idx, NULL, 0, SQLITE_STATIC);
            if (CSORMA_TRACE) { CSORMA_LOGGER_ALWAYS("binding(type:%s) %d is NULL", BINDVAR_TYPE_NAME[bt], bindvar_idx); }
        } else {
            sqlite3_bind_text(stmt, bindvar_idx, (const char *)str_value->s,
                str_value->l, SQLITE_STATIC);
            if (CSORMA_TRACE) { CSORMA_LOGGER_ALWAYS("binding(type:%s) %d=%s", BINDVAR_TYPE_NAME[bt], bindvar_idx, (const char *)str_value->s); }
        }
    }
}

void bind_all_set_bindvars(sqlite3_stmt *stmt, const OrmaBindvars *bind_set_vars)
{
    // HINT: bind all "SET" bindvars
    if (bind_set_vars != NULL)
    {
        if ((bind_set_vars->b != NULL) && (bind_set_vars->items > 0))
        {
            OrmaBindvar *b_cur = bind_set_vars->b;
            for(int i=0;i<bind_set_vars->items;i++)
            {
                BINDVAR_TYPE bt = b_cur->t;
                CSORMA_LOGGER_DEBUG("binding(type:%d) %d", bt, i + __BINDVAR_OFFSET_SET);
                if (bt == BINDVAR_TYPE_Int)
                {
                    sqlite3_bind_int(stmt, i + __BINDVAR_OFFSET_SET, b_cur->n);
                    if (CSORMA_TRACE) { CSORMA_LOGGER_ALWAYS("binding(type:%s) %d=%d", BINDVAR_TYPE_NAME[bt], i + __BINDVAR_OFFSET_SET, (int32_t)b_cur->n); }
                }
                else if (bt == BINDVAR_TYPE_Long)
                {
                    sqlite3_bind_int64(stmt, i + __BINDVAR_OFFSET_SET, b_cur->n);
                    if (CSORMA_TRACE) { CSORMA_LOGGER_ALWAYS("binding(type:%s) %d=%d", BINDVAR_TYPE_NAME[bt], i + __BINDVAR_OFFSET_SET, (int64_t)b_cur->n); }
                }
                else if (bt == BINDVAR_TYPE_Boolean)
                {
                    sqlite3_bind_int(stmt, i + __BINDVAR_OFFSET_SET, b_cur->n);
                    if (CSORMA_TRACE) { CSORMA_LOGGER_ALWAYS("binding(type:%s) %d=%d", BINDVAR_TYPE_NAME[bt], i + __BINDVAR_OFFSET_SET, (bool)b_cur->n); }
                }
                else if (bt == BINDVAR_TYPE_String)
                {
                    if (b_cur->s == NULL) {
                        sqlite3_bind_text(stmt, i + __BINDVAR_OFFSET_SET, NULL, 0, SQLITE_STATIC);
                        if (CSORMA_TRACE) { CSORMA_LOGGER_ALWAYS("binding(type:%s) %d is NULL", BINDVAR_TYPE_NAME[bt], i + __BINDVAR_OFFSET_SET); }
                    } else {
                        sqlite3_bind_text(stmt, i + __BINDVAR_OFFSET_SET, (const char *)b_cur->s->s,
                                b_cur->s->l, SQLITE_STATIC);
                        if (CSORMA_TRACE) { CSORMA_LOGGER_ALWAYS("binding(type:%s) %d=%s", BINDVAR_TYPE_NAME[bt], i + __BINDVAR_OFFSET_SET, (const char *)b_cur->s->s); }
                    }
                }
                b_cur++;
            }
        }
    }
}

void bind_all_where_bindvars(sqlite3_stmt *stmt, const OrmaBindvars *bind_where_vars)
{
    // HINT: bind all "WHERE" bindvars
    if (bind_where_vars != NULL)
    {
        if ((bind_where_vars->b != NULL) && (bind_where_vars->items > 0))
        {
            OrmaBindvar *b_cur = bind_where_vars->b;
            for(int i=0;i<bind_where_vars->items;i++)
            {
                BINDVAR_TYPE bt = b_cur->t;
                CSORMA_LOGGER_DEBUG("binding(type:%d) %d", bt, i + __BINDVAR_OFFSET_WHERE);
                if (bt == BINDVAR_TYPE_Int)
                {
                    sqlite3_bind_int(stmt, i + __BINDVAR_OFFSET_WHERE, b_cur->n);
                    if (CSORMA_TRACE) { CSORMA_LOGGER_ALWAYS("binding(type:%s) %d=%d", BINDVAR_TYPE_NAME[bt], i + __BINDVAR_OFFSET_WHERE, (int32_t)b_cur->n); }
                }
                else if (bt == BINDVAR_TYPE_Long)
                {
                    sqlite3_bind_int64(stmt, i + __BINDVAR_OFFSET_WHERE, b_cur->n);
                    if (CSORMA_TRACE) { CSORMA_LOGGER_ALWAYS("binding(type:%s) %d=%d", BINDVAR_TYPE_NAME[bt], i + __BINDVAR_OFFSET_WHERE, (int64_t)b_cur->n); }
                }
                else if (bt == BINDVAR_TYPE_Boolean)
                {
                    sqlite3_bind_int(stmt, i + __BINDVAR_OFFSET_WHERE, b_cur->n);
                    if (CSORMA_TRACE) { CSORMA_LOGGER_ALWAYS("binding(type:%s) %d=%d", BINDVAR_TYPE_NAME[bt], i + __BINDVAR_OFFSET_WHERE, (bool)b_cur->n); }
                }
                else if (bt == BINDVAR_TYPE_String)
                {
                    if (b_cur->s == NULL) {
                        sqlite3_bind_text(stmt, i + __BINDVAR_OFFSET_WHERE, NULL, 0, SQLITE_STATIC);
                        if (CSORMA_TRACE) { CSORMA_LOGGER_ALWAYS("binding(type:%s) %d is NULL", BINDVAR_TYPE_NAME[bt], i + __BINDVAR_OFFSET_WHERE); }
                    } else {
                        sqlite3_bind_text(stmt, i + __BINDVAR_OFFSET_WHERE, (const char *)b_cur->s->s,
                                b_cur->s->l, SQLITE_STATIC);
                        if (CSORMA_TRACE) { CSORMA_LOGGER_ALWAYS("binding(type:%s) %d=%s", BINDVAR_TYPE_NAME[bt], i + __BINDVAR_OFFSET_WHERE, (const char *)b_cur->s->s); }
                    }
                }
                b_cur++;
            }
        }
    }
}

void bind_to_set_sql_int(csorma_s *sql_set, OrmaBindvars *bind_set_vars, const char *static_text,
                        int64_t value_int_any, const BINDVAR_TYPE bt)
{
    sql_set = csorma_str_con(sql_set, static_text, strlen(static_text));
    sql_set = csorma_str_int32t(sql_set, __BINDVAR_OFFSET_SET + bind_set_vars->items);
    sql_set = csorma_str_con_space(sql_set);
    if (bt == BINDVAR_TYPE_Long)
    {
        bind_set_vars = bindvar_add_n(bind_set_vars, value_int_any, BINDVAR_TYPE_Long);
    }
    else if (bt == BINDVAR_TYPE_Int)
    {
        bind_set_vars = bindvar_add_n(bind_set_vars, (int32_t)value_int_any, BINDVAR_TYPE_Int);
    }
    else if (bt == BINDVAR_TYPE_Boolean)
    {
        bind_set_vars = bindvar_add_n(bind_set_vars, (bool)value_int_any, BINDVAR_TYPE_Boolean);
    }
}

void bind_to_set_sql_string(csorma_s *sql_set, OrmaBindvars *bind_set_vars, const char *static_text,
                        csorma_s *value_str, const BINDVAR_TYPE UNUSED(bt))
{
    sql_set = csorma_str_con(sql_set, static_text, strlen(static_text));
    sql_set = csorma_str_int32t(sql_set, __BINDVAR_OFFSET_SET + bind_set_vars->items);
    sql_set = csorma_str_con_space(sql_set);
    bind_set_vars = bindvar_add_s(bind_set_vars, value_str);
}

void add_to_orderby_asc_sql(csorma_s *sql_orderby, const char *column_name, const bool asc)
{
    if ((sql_orderby == NULL) || (sql_orderby->l == 0))
    {
        const char* st1 = " order by ";
        sql_orderby = csorma_str_con(sql_orderby, st1, strlen(st1));
    }
    else
    {
        const char* st2 = " , ";
        sql_orderby = csorma_str_con(sql_orderby, st2, strlen(st2));
    }
    sql_orderby = csorma_str_con(sql_orderby, column_name, strlen(column_name));
    sql_orderby = csorma_str_con_space(sql_orderby);
    if (asc)
    {
        const char* st3 = " ASC ";
        sql_orderby = csorma_str_con(sql_orderby, st3, strlen(st3));
    }
    else
    {
        const char* st4 = " DESC ";
        sql_orderby = csorma_str_con(sql_orderby, st4, strlen(st4));
    }
}

void bind_to_where_sql_int(csorma_s *sql_where, OrmaBindvars *bind_where_vars, const char *static_text,
                        int64_t value_int_any, const BINDVAR_TYPE bt, const char* static_post_text)
{
    sql_where = csorma_str_con(sql_where, static_text, strlen(static_text));
    sql_where = csorma_str_int32t(sql_where, __BINDVAR_OFFSET_WHERE + bind_where_vars->items);
    sql_where = csorma_str_con_space(sql_where);
    sql_where = csorma_str_con(sql_where, static_post_text, strlen(static_post_text));
    if (bt == BINDVAR_TYPE_Long)
    {
        bind_where_vars = bindvar_add_n(bind_where_vars, value_int_any, BINDVAR_TYPE_Long);
    }
    else if (bt == BINDVAR_TYPE_Int)
    {
        bind_where_vars = bindvar_add_n(bind_where_vars, (int32_t)value_int_any, BINDVAR_TYPE_Int);
    }
    else if (bt == BINDVAR_TYPE_Boolean)
    {
        bind_where_vars = bindvar_add_n(bind_where_vars, (bool)value_int_any, BINDVAR_TYPE_Boolean);
    }
}

void bind_to_where_sql_string(csorma_s *sql_where, OrmaBindvars *bind_where_vars, const char *static_text,
                        csorma_s *value_str, const BINDVAR_TYPE UNUSED(bt), const char* static_post_text)
{
    sql_where = csorma_str_con(sql_where, static_text, strlen(static_text));
    sql_where = csorma_str_int32t(sql_where, __BINDVAR_OFFSET_WHERE + bind_where_vars->items);
    sql_where = csorma_str_con_space(sql_where);
    sql_where = csorma_str_con(sql_where, static_post_text, strlen(static_post_text));
    bind_where_vars = bindvar_add_s(bind_where_vars, value_str);
}

void add_to_where_sql_string(csorma_s *sql_where, const char *static_text)
{
    sql_where = csorma_str_con(sql_where, static_text, strlen(static_text));
}

static uint8_t* str_buf_concat(const uint8_t *b1, const uint32_t b1_len, const uint8_t *b2, const uint32_t b2_len)
{
    uint8_t *out = calloc(1, b1_len + b2_len + 1);
    if (out == NULL)
    {
        return NULL;
    }
    if (b1_len > 0)
    {
        memcpy(out, b1, b1_len);
    }
    if (b2_len > 0)
    {
        memcpy(out + b1_len, b2, b2_len);
    }
    return out;
}

void OrmaDatabase_lock_lastrowid_mutex(void)
{
    CSORMA_LOGGER_DEBUG("trying to lock lastrowid mutex");
    pthread_mutex_lock(&__sorma_global_last_inserted_rowid___mutex);
    CSORMA_LOGGER_DEBUG("mutex lastrowid locked");
}

void OrmaDatabase_unlock_lastrowid_mutex(void)
{
    CSORMA_LOGGER_DEBUG("trying to UN-lock lastrowid mutex");
    pthread_mutex_unlock(&__sorma_global_last_inserted_rowid___mutex);
    CSORMA_LOGGER_DEBUG("mutex lastrowid UN-locked");
}

OrmaDatabase* OrmaDatabase_init(const uint8_t *directory_name, const uint32_t directory_name_len, 
                                const uint8_t *file_name, const uint32_t file_name_len)
{
    const uint8_t *db_file_with_path = str_buf_concat(directory_name, directory_name_len, file_name, file_name_len);
    if (db_file_with_path == NULL)
    {
        CSORMA_LOGGER_ERROR("error building path buffer");
        return NULL;
    }
    sqlite3 *db = NULL;
    int rc = sqlite3_open((const char*)db_file_with_path, &db);
    free((void *)db_file_with_path);
    if (rc != SQLITE_OK) {
        CSORMA_LOGGER_ERROR("cannot open database: %s", sqlite3_errmsg(db));
        sqlite3_close(db);
        return NULL;
    }
    CSORMA_LOGGER_DEBUG("creating database");
    OrmaDatabase *o = (OrmaDatabase*)calloc(1, sizeof(OrmaDatabase));

    if (pthread_mutex_init(&__sorma_global_last_inserted_rowid___mutex, NULL) != 0)
    {
        CSORMA_LOGGER_ERROR("error creating __sorma_global_last_inserted_rowid___mutex");
        CSORMA_LOGGER_DEBUG("closing database");
        sqlite3_close(db);
        free(o);
        CSORMA_LOGGER_DEBUG("database closed");
        return NULL;
    }
    CSORMA_LOGGER_DEBUG("__sorma_global_last_inserted_rowid___mutex created");

    CSORMA_LOGGER_DEBUG("database created");
    o->db = db;
    CSORMA_LOGGER_DEBUG("o->db: %p db: %p", o->db, db);
    o->user_data = NULL;

    return o;
}

int OrmaDatabase_key(OrmaDatabase *o, const uint8_t *key, const uint32_t key_len)
{
#ifdef ENCRYPT_CSORMA
    int result = sqlite3_key(o->db, key, key_len);
    return result;
#else
    // HINT: to get rid of unused var warning
    (void)o;
    (void)key;
    (void)key_len;
    return CSORMA_GENERIC_RESULT_ERROR;
#endif
}

CSORMA_GENERIC_RESULT OrmaDatabase_set_wal_mode(OrmaDatabase *o, const bool use_wal)
{
    if (use_wal) {
        // HINT: turn on WAL mode. this will persist also when you close and reopen the DB
        return OrmaDatabase_run_multi_sql(o, (const uint8_t *)"PRAGMA journal_mode = WAL;");
    } else {
        // HINT: turn off WAL mode. this will persist also when you close and reopen the DB
        return OrmaDatabase_run_multi_sql(o, (const uint8_t *)"PRAGMA journal_mode = DELETE;");
    }
}

void OrmaDatabase_shutdown(OrmaDatabase *o)
{
    if (o == NULL)
    {
        CSORMA_LOGGER_INFO("database already shutdown");
        return;
    }
    CSORMA_LOGGER_DEBUG("closing database");
    sqlite3_close(o->db);
    CSORMA_LOGGER_DEBUG("database closed");
    o->db = NULL;
    o->user_data = NULL;
    CSORMA_LOGGER_DEBUG("freeing buffer");
    free(o);
    CSORMA_LOGGER_DEBUG("buffer freed");
    o = NULL;
}

CSORMA_GENERIC_RESULT OrmaDatabase_run_multi_sql(const OrmaDatabase *o, const uint8_t *sqltxt)
{
    if (o == NULL)
    {
        CSORMA_LOGGER_ERROR("database struct is NULL");
        return CSORMA_GENERIC_RESULT_ERROR;
    }
    if (o->db == NULL)
    {
        CSORMA_LOGGER_DEBUG("database handle is NULL");
        return CSORMA_GENERIC_RESULT_ERROR;
    }

    char *err_msg = NULL;
    int rc = sqlite3_exec(o->db, (const char*)sqltxt, 0, 0, &err_msg);

    if (rc != SQLITE_OK ) {
        CSORMA_LOGGER_DEBUG("SQL error: %s", err_msg);
        sqlite3_free(err_msg);        
    } else {
        CSORMA_LOGGER_DEBUG("SQL executed successfully");
        return CSORMA_GENERIC_RESULT_OK;
    }

    return CSORMA_GENERIC_RESULT_ERROR;
}

const char *csorma_get_sqlite_version(void)
{
    return sqlite3_libversion();
}

const char *csorma_get_version(void)
{
#if defined(__SANITIZE_ADDRESS__)
    return csorma_global_version_asan_string;
#else
    return csorma_global_version_string;
#endif
}

const char *csorma_get_sqlcipher_version(void)
{
#ifdef ENCRYPT_CSORMA
    // TODO: have not found a way to get the version per function call. without crash or using `free` somewhere.
    //       so this is now updated by hand.

    // !! the hex code in the next line is used by the 'download_sqlcipher_amalgamation.sh' to find this line and update the version string !!
    return "4.9.0 community"; // DO NOT REMOVE THIS: 0x0ffca123459837347ca6c5a8
#else
    return "0.0.0";
#endif
}


static int rs_find_column_idx(sqlite3_stmt *res, const char *column_name)
{
    int result_colum_count = sqlite3_column_count(res);
    CSORMA_LOGGER_DEBUG("result_colum_count=%d", result_colum_count);
    for (int i=0;i<result_colum_count;i++)
    {
        const char *col_name;
        col_name = sqlite3_column_name(res, i);
        if (col_name != NULL)
        {
            if (strncmp(col_name, column_name, strlen(column_name)) == 0)
            {
                CSORMA_LOGGER_DEBUG("column found #%d %s", i, col_name);
                return i;
            }
        }
    }
    // HINT: return -1 on error
    return -1;
}

int64_t __rs_getLong(sqlite3_stmt *res, const char *column_name)
{
    return sqlite3_column_int64(res, rs_find_column_idx(res, column_name));
}

csorma_s* __rs_getString(sqlite3_stmt *res, const char *column_name)
{
    csorma_s *out = NULL;
    const unsigned char* result = sqlite3_column_text(res, rs_find_column_idx(res, column_name));
    if (result == NULL)
    {
        CSORMA_LOGGER_DEBUG("null string found");
        out = csorma_str2_build("");
    }
    else
    {
        CSORMA_LOGGER_DEBUG("string len=%d", strlen((const char *)result));
        out = csorma_str2_build((const char *)result);
    }
    return out;
}

int32_t __rs_getInt(sqlite3_stmt *res, const char *column_name)
{
    return sqlite3_column_int(res, rs_find_column_idx(res, column_name));
}

bool __rs_getBoolean(sqlite3_stmt *res, const char *column_name)
{
    bool ret = false;
    int tmp = sqlite3_column_int(res, rs_find_column_idx(res, column_name));
    /*
     * we use the (hopefully std C) definition of bool:
     *                     0 -> false
     * any other "int" value -> true
     */
    if (tmp != 0)
    {
        ret = true;
    }
    return ret;
}

#ifdef __cplusplus
}  // extern "C"
#endif
