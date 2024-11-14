#include "__@@@TABLE@@@__.h"
#include "logger.h"
#include "csorma.h"
#include "sqlite/sqlite3.h"
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

static void __free_all_bindvars(__@@@TABLE@@@__ *t)
{
    bindvar_free(t->bind_set_vars);
    bindvar_free(t->bind_where_vars);
}

static __@@@TABLE@@@__List* __append___@@@TABLElc@@@___list(__@@@TABLE@@@__List *l, __@@@TABLE@@@__ *t)
{
    if (l == NULL)
    {
        return NULL;
    }
    int psize = sizeof(__@@@TABLE@@@__ *);
    int size = psize * (l->items + 1);
    l->l = realloc(l->l, size);
    uint8_t *m_t = (uint8_t *)l->l;
    m_t = m_t + (l->items * psize);
    memset(m_t, 0, psize);
    __@@@TABLE@@@__ **mt2 = l->l;
    mt2 = mt2 + l->items;
    *mt2 = t;
    l->items++;
    return l;
}

// --------- main DB access functions ---------
// --------- main DB access functions ---------
// --------- main DB access functions ---------

static __@@@TABLE@@@__List* _to_list(__@@@TABLE@@@__* t)
{
    __@@@TABLE@@@__List *result = calloc(1, sizeof(__@@@TABLE@@@__List));
    result->items = 0;
    result->l = NULL;

    t->sql_start = csorma_str_con(t->sql_start, __SELECT_START, strlen(__SELECT_START));
    t->sql_start = csorma_str_con(t->sql_start, "\"", strlen("\""));
    t->sql_start = csorma_str_con(t->sql_start, __TABLE_NAME, strlen(__TABLE_NAME));
    t->sql_start = csorma_str_con(t->sql_start, "\"", strlen("\""));

    sqlite3_stmt *res;
    csorma_s *sql_txt = csorma_str_con2(NULL, t->sql_start);
    sql_txt = csorma_str_con2(sql_txt, t->sql_where);
    sql_txt = csorma_str_con2(sql_txt, t->sql_orderby);
    if (CSORMA_TRACE) { CSORMA_LOGGER_ALWAYS("%s", sql_txt->s); }

    int rc = sqlite3_prepare_v2(t->db, (const char *)sql_txt->s, -1, &res, 0);
    CSORMA_LOGGER_DEBUG("rc=%d", rc);
    CSORMA_LOGGER_DEBUG("err=%s", sqlite3_errmsg(t->db));

    if (rc == SQLITE_OK)
    {
        bind_all_where_bindvars(res, t->bind_where_vars);
    }
    else
    {
        CSORMA_LOGGER_ERROR("execute err=%s", sqlite3_errmsg(t->db));
    }

    int step;
    uint64_t row_count = 0;
    while (1 == 1)
    {
        step = sqlite3_step(res);
        CSORMA_LOGGER_DEBUG("step=%d", step);
        if (step == SQLITE_ROW)
        {
            row_count++;
            CSORMA_LOGGER_DEBUG("row found #%lu", row_count);
            int result_colum_count = sqlite3_column_count(res);
            CSORMA_LOGGER_DEBUG("result_colum_count=%d", result_colum_count);

            // --------------------------------
            __@@@TABLE@@@__ *tx = __new___@@@TABLElc@@@__(t->db);
            // -----
__@@@COLUMNS_SETTERS_01@@@__
            // -----
            result = __append___@@@TABLElc@@@___list(result, tx);
            // --------------------------------
        }
        else if (step == SQLITE_BUSY)
        {
            continue;
        }
        else if (step == SQLITE_DONE)
        {
            CSORMA_LOGGER_DEBUG("select finished");
            break;
        }
        else
        {
            CSORMA_LOGGER_ERROR("some error occured");
            break;
        }
    }
    CSORMA_LOGGER_DEBUG("sqlite3_finalize");
    sqlite3_finalize(res);

    csorma_str_free(sql_txt);
    __free___@@@TABLElc@@@__(t);

    return result;
}

static int64_t _count(__@@@TABLE@@@__* t)
{
    int64_t result = -1;

    t->sql_start = csorma_str_con(t->sql_start, __SELECT_COUNT_START, strlen(__SELECT_COUNT_START));
    t->sql_start = csorma_str_con(t->sql_start, "\"", strlen("\""));
    t->sql_start = csorma_str_con(t->sql_start, __TABLE_NAME, strlen(__TABLE_NAME));
    t->sql_start = csorma_str_con(t->sql_start, "\"", strlen("\""));

    sqlite3_stmt *res;
    csorma_s *sql_txt = csorma_str_con2(NULL, t->sql_start);
    sql_txt = csorma_str_con2(sql_txt, t->sql_where);
    if (CSORMA_TRACE) { CSORMA_LOGGER_ALWAYS("%s", sql_txt->s); }

    int rc = sqlite3_prepare_v2(t->db, (const char *)sql_txt->s, -1, &res, 0);
    CSORMA_LOGGER_DEBUG("rc=%d", rc);
    CSORMA_LOGGER_DEBUG("err=%s", sqlite3_errmsg(t->db));

    if (rc == SQLITE_OK)
    {
        bind_all_where_bindvars(res, t->bind_where_vars);
        int step = sqlite3_step(res);
        CSORMA_LOGGER_DEBUG("step=%d", step);
        if (step == SQLITE_ROW)
        {
            result = sqlite3_column_int64(res, 0);
            CSORMA_LOGGER_DEBUG("%lld ", (long long)result);
        }
        else
        {
            CSORMA_LOGGER_ERROR("execute err=%s", sqlite3_errmsg(t->db));
            result = -2;
        }
    }
    else
    {
        CSORMA_LOGGER_ERROR("execute err=%s", sqlite3_errmsg(t->db));
        result = -3;
    }

    CSORMA_LOGGER_DEBUG("sqlite3_finalize");
    sqlite3_finalize(res);

    csorma_str_free(sql_txt);
    __free___@@@TABLElc@@@__(t);

    return result;
}

static int64_t _execute(__@@@TABLE@@@__ *t)
{
    int64_t afftect_rows = -1;

    if (t == NULL)
    {
        return afftect_rows;
    }

    sqlite3_stmt *res;
    csorma_s *sql_txt = csorma_str_con2(NULL, t->sql_start);
    sql_txt = csorma_str_con2(sql_txt, t->sql_set);
    sql_txt = csorma_str_con2(sql_txt, t->sql_where);
    if (CSORMA_TRACE) { CSORMA_LOGGER_ALWAYS("%s", sql_txt->s); }

    int rc = sqlite3_prepare_v2(t->db, (const char *)sql_txt->s, -1, &res, 0);
    CSORMA_LOGGER_DEBUG("rc=%d", rc);
    CSORMA_LOGGER_DEBUG("err=%s", sqlite3_errmsg(t->db));

    if (rc == SQLITE_OK)
    {
        bind_all_set_bindvars(res, t->bind_set_vars);
        bind_all_where_bindvars(res, t->bind_where_vars);

        OrmaDatabase_lock_lastrowid_mutex();
        int step = sqlite3_step(res);
        CSORMA_LOGGER_DEBUG("step=%d", step);

        if (step != SQLITE_DONE)
        {
            CSORMA_LOGGER_ERROR("execute err=%s", sqlite3_errmsg(t->db));
            afftect_rows = -2;
        }
        else
        {
            afftect_rows = (int64_t)sqlite3_changes64(t->db);
        }
        OrmaDatabase_unlock_lastrowid_mutex();
    }
    else
    {
        CSORMA_LOGGER_ERROR("execute err=%s", sqlite3_errmsg(t->db));
        afftect_rows = -3;
    }

    CSORMA_LOGGER_DEBUG("sqlite3_finalize");
    sqlite3_finalize(res);

    csorma_str_free(sql_txt);
    __free___@@@TABLElc@@@__(t);

    return afftect_rows;
}

int64_t __insert_into___@@@TABLElc@@@__(__@@@TABLE@@@__ *t)
{
    int64_t last_insert_id = -1;

    if (t == NULL)
    {
        return last_insert_id;
    }

    t->sql_start = csorma_str_con(t->sql_start, __INSERT_START, strlen(__INSERT_START));
    t->sql_start = csorma_str_con(t->sql_start, "\"", strlen("\""));
    t->sql_start = csorma_str_con(t->sql_start, __TABLE_NAME, strlen(__TABLE_NAME));
    t->sql_start = csorma_str_con(t->sql_start, "\"", strlen("\""));

    sqlite3_stmt *res;
    csorma_s *sql_txt = csorma_str_con2(NULL, t->sql_start);

__@@@COLUMNS_INSERTER_01@@@__

    sql_txt = csorma_str_con(sql_txt, sql1, strlen(sql1));
    if (CSORMA_TRACE) { CSORMA_LOGGER_ALWAYS("%s", sql_txt->s); }

    int rc = sqlite3_prepare_v2(t->db, (const char *)sql_txt->s, -1, &res, 0);
    CSORMA_LOGGER_DEBUG("rc=%d", rc);
    CSORMA_LOGGER_DEBUG("err=%s", sqlite3_errmsg(t->db));

    if (rc == SQLITE_OK)
    {
__@@@COLUMNS_INSERTER_BIND_02@@@__

        OrmaDatabase_lock_lastrowid_mutex();
        int step = sqlite3_step(res);
        if (step != SQLITE_DONE)
        {
            CSORMA_LOGGER_ERROR("insert err=%s", sqlite3_errmsg(t->db));
            last_insert_id = -2;
        }
        else
        {
            // HINT: we (sadly) need to globally guard this, because last inserted row id is global per database connection!
            last_insert_id = sqlite3_last_insert_rowid(t->db);
            CSORMA_LOGGER_DEBUG("The last Id of the inserted row is %ld", last_insert_id);
            if (CSORMA_TRACE) { CSORMA_LOGGER_ALWAYS("last inserted rowid: %ld", last_insert_id); }
        }
        OrmaDatabase_unlock_lastrowid_mutex();
    }
    else
    {
        CSORMA_LOGGER_ERROR("execute err=%s", sqlite3_errmsg(t->db));
        last_insert_id = -3;
    }

    CSORMA_LOGGER_DEBUG("sqlite3_finalize");
    sqlite3_finalize(res);

    csorma_str_free(sql_txt);

    return last_insert_id;
}

// --------- main DB access functions ---------
// --------- main DB access functions ---------
// --------- main DB access functions ---------

// --------- column functions ---------
// --------- column functions ---------
// --------- column functions ---------

__@@@FUNCS_EQ02@@@__

__@@@FUNCS_SET02@@@__

// --------- column functions ---------
// --------- column functions ---------
// --------- column functions ---------

void __free___@@@TABLElc@@@___list(__@@@TABLE@@@__List *l)
{
    if (l == NULL)
    {
        return;
    }

    if (l->items == 0)
    {
        free(l);
        return;
    }

    if (l->l == NULL)
    {
        return;
    }

    __@@@TABLE@@@__ **mt = l->l;
    for(int i=0;i<l->items;i++)
    {
        if (mt != NULL)
        {
            __free___@@@TABLElc@@@__(*mt);
        }
        mt++;
    }
    free(l->l);
    free(l);
}

void __free___@@@TABLElc@@@__(__@@@TABLE@@@__ *t)
{
    if (t == NULL)
    {
        return;
    }

    // ------------------------
    __free_all_bindvars(t);
    // ------------------------
__@@@FUNCS_FREE_STRS01@@@__
    // ------------------------
    csorma_str_free(t->sql_start);
    csorma_str_free(t->sql_where);
    csorma_str_free(t->sql_orderby);
    csorma_str_free(t->sql_set);
    // ------------------------
    free(t);
    // ------------------------
}

__@@@TABLE@@@__* __new___@@@TABLElc@@@__(void *db)
{
    __@@@TABLE@@@__ *t = calloc(1, sizeof(__@@@TABLE@@@__));
    // --------------
    t->sql_where = csorma_str_con(t->sql_where, __WHERE_INIT, strlen(__WHERE_INIT));
    CSORMA_LOGGER_DEBUG("sql_where:%p %s", t->sql_where, t->sql_where->s);
    t->sql_set = csorma_str_con(t->sql_set, __SET_INIT, strlen(__SET_INIT));
    CSORMA_LOGGER_DEBUG("sql_set:%p %s", t->sql_set, t->sql_set->s);
    t->sql_orderby = csorma_str_con(t->sql_orderby, __ORDER_BY, strlen(__ORDER_BY));
    CSORMA_LOGGER_DEBUG("sql_orderby:%p %s", t->sql_orderby, t->sql_orderby->s);
    // --------------
    t->bind_where_vars = bindvar_init(t->bind_where_vars);
    t->bind_set_vars = bindvar_init(t->bind_set_vars);
    // --------------


    // ----- eq functions ---------
__@@@FUNCS_EQ03@@@__
    // ----- eq functions ---------


    // ----- set functions ---------
__@@@FUNCS_SET03@@@__
    // ----- set functions ---------


    // --------------
    int64_t (*_FuncPtr001) (__@@@TABLE@@@__*);
    _FuncPtr001 = &_count;
    t->count = _FuncPtr001;
    // --------------
    int64_t (*_FuncPtr002) (__@@@TABLE@@@__*);
    _FuncPtr002 = &_execute;
    t->execute = _FuncPtr002;
    // --------------
    __@@@TABLE@@@__List* (*_FuncPtr003) (__@@@TABLE@@@__*);
    _FuncPtr003 = &_to_list;
    t->toList = _FuncPtr003;
    // --------------
    t->db = (sqlite3 *)db;
    CSORMA_LOGGER_DEBUG("db=%p", db);
    // --------------
    return t;
}

__@@@TABLE@@@__* __select_from___@@@TABLElc@@@__(void *db)
{
    CSORMA_LOGGER_DEBUG("db: %p", db);
    return __new___@@@TABLElc@@@__(db);
}

__@@@TABLE@@@__* __update___@@@TABLElc@@@__(void *db)
{
    CSORMA_LOGGER_DEBUG("db: %p", db);
    __@@@TABLE@@@__ *t = __new___@@@TABLElc@@@__(db);
    t->sql_start = csorma_str_con(t->sql_start, __UPDATE_START, strlen(__UPDATE_START));
    t->sql_start = csorma_str_con(t->sql_start, "\"", strlen("\""));
    t->sql_start = csorma_str_con(t->sql_start, __TABLE_NAME, strlen(__TABLE_NAME));
    t->sql_start = csorma_str_con(t->sql_start, "\"", strlen("\""));
    return t;
}

__@@@TABLE@@@__* __delete_from___@@@TABLElc@@@__(void *db)
{
    CSORMA_LOGGER_DEBUG("db: %p", db);
    __@@@TABLE@@@__ *t = __new___@@@TABLElc@@@__(db);
    t->sql_start = csorma_str_con(t->sql_start, __DELETE_START, strlen(__DELETE_START));
    t->sql_start = csorma_str_con(t->sql_start, "\"", strlen("\""));
    t->sql_start = csorma_str_con(t->sql_start, __TABLE_NAME, strlen(__TABLE_NAME));
    t->sql_start = csorma_str_con(t->sql_start, "\"", strlen("\""));
    return t;
}

#ifdef __cplusplus
}  // extern "C"
#endif
