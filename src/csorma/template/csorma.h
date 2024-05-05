
#ifndef C_CSORMA_CSORMA_H
#define C_CSORMA_CSORMA_H

#include "sqlite/sqlite3.h"
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

// ----------- version -----------
// ----------- version -----------
#define CSORMA_VERSION_MAJOR 0
#define CSORMA_VERSION_MINOR 99
#define CSORMA_VERSION_PATCH 0
static const char csorma_global_version_string[] = "0.99.0";
static const char csorma_global_version_asan_string[] = "0.99.0-ASAN";

#define CSORMA__GIT_COMMIT_HASH "00000007"
// ----------- version -----------
// ----------- version -----------

#define CSORMA_TRACE 0 // to log all SQL statements set this to 1

#define __SELECT_START "SELECT * FROM "
#define __SELECT_COUNT_START "SELECT count(*) as count FROM "
#define __INSERT_START "INSERT INTO "
#define __UPDATE_START "UPDATE "
#define __DELETE_START "DELETE FROM "

#define __WHERE_INIT " WHERE 1=1 "
#define __SET_INIT ""
#define __ORDER_BY ""

typedef enum BINDVAR_TYPE {
    BINDVAR_TYPE_Int = 0,
    BINDVAR_TYPE_Long = 1,
    BINDVAR_TYPE_String = 2,
    BINDVAR_TYPE_Boolean = 3,
} BINDVAR_TYPE;

#define _BIND_NaN 0 // can be used and number type or NULL pointer (but still be careful!!)

typedef enum CSORMA_GENERIC_RESULT {
    CSORMA_GENERIC_RESULT_OK = 0,
    CSORMA_GENERIC_RESULT_ERROR = 9999,
} CSORMA_GENERIC_RESULT;

extern const char* BINDVAR_TYPE_NAME[];

#define __BINDVAR_OFFSET_WHERE 400
#define __BINDVAR_OFFSET_SET 600

// ----- shortcuts functions -----
#define csb(b1) csorma_str2_build(b1)
#define csc(b1,b2) csorma_str_con(NULL,b1,b2)
// ----- shortcuts functions -----

typedef struct OrmaDatabase {
    void *user_data;
    sqlite3 *db;
} OrmaDatabase;

typedef struct csorma_s {
    uint8_t* cur;
    uint32_t l;
    uint8_t n;
    uint8_t* s;
} csorma_s;

typedef struct OrmaBindvar {
    BINDVAR_TYPE t;
    int64_t n;
    csorma_s* s;
} OrmaBindvar;

typedef struct OrmaBindvars {
    int64_t items;
    OrmaBindvar* b;
} OrmaBindvars;

const char *csorma_get_version();
const char *csorma_get_sqlite_version();

csorma_s *csorma_str2_build(const char *b1);
csorma_s *csorma_str_build(const char *b1, const uint32_t b1_len);
csorma_s *csorma_str_con2(csorma_s *out, csorma_s *append);
csorma_s *csorma_str_con_space(csorma_s *out);
csorma_s *csorma_str_int32t(csorma_s *out, const int32_t append_i);
csorma_s *csorma_str_con(csorma_s *out, const char *b1, const uint32_t b1_len);
void csorma_str_free(csorma_s *s);

int64_t __rs_getLong(sqlite3_stmt *res, const char *column_name);
csorma_s* __rs_getString(sqlite3_stmt *res, const char *column_name);
int32_t __rs_getInt(sqlite3_stmt *res, const char *column_name);
bool __rs_getBoolean(sqlite3_stmt *res, const char *column_name);

OrmaBindvars *bindvar_init(OrmaBindvars *b);
OrmaBindvars *bindvar_add_s(OrmaBindvars *b, csorma_s *s);
OrmaBindvars *bindvar_add_n(OrmaBindvars *b, int64_t n, const BINDVAR_TYPE t);
void bindvar_dump(OrmaBindvars *b, int32_t offset);
void bindvar_free(OrmaBindvars *b);
void bindvar_to_stmt(sqlite3_stmt *stmt, int32_t bindvar_idx, const BINDVAR_TYPE bt,
        const int32_t int_value, const int64_t int64_value, const csorma_s *str_value);
void bind_all_set_bindvars(sqlite3_stmt *stmt, const OrmaBindvars *bind_set_vars);
void bind_all_where_bindvars(sqlite3_stmt *stmt, const OrmaBindvars *bind_where_vars);
void bind_to_set_sql_int(csorma_s *sql_set, OrmaBindvars *bind_set_vars, const char *static_text,
                        int64_t value_int_any, const BINDVAR_TYPE bt);
void bind_to_set_sql_string(csorma_s *sql_set, OrmaBindvars *bind_set_vars, const char *static_text,
                        csorma_s *value_str, const BINDVAR_TYPE bt);
void bind_to_where_sql_int(csorma_s *sql_where, OrmaBindvars *bind_where_vars, const char *static_text,
                        int64_t value_int_any, const BINDVAR_TYPE bt, const char* static_post_text);
void bind_to_where_sql_string(csorma_s *sql_where, OrmaBindvars *bind_where_vars, const char *static_text,
                        csorma_s *value_str, const BINDVAR_TYPE bt, const char* static_post_text);
void add_to_orderby_asc_sql(csorma_s *sql_orderby, const char *column_name, const bool asc);

OrmaDatabase* OrmaDatabase_init(const uint8_t *directory_name, const uint32_t directory_name_len, 
                                const uint8_t *file_name, const uint32_t file_name_len);

void OrmaDatabase_lock_lastrowid_mutex();
void OrmaDatabase_unlock_lastrowid_mutex();

void OrmaDatabase_shutdown(OrmaDatabase *o);

CSORMA_GENERIC_RESULT OrmaDatabase_run_multi_sql(const OrmaDatabase *o, const uint8_t *sqltxt);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // C_CSORMA_CSORMA_H

