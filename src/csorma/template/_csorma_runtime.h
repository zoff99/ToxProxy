
#ifndef C_CSORMA_CSORMA_RUNTIME_H
#define C_CSORMA_CSORMA_RUNTIME_H

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum CSORMA_GENERIC_RESULT {
    CSORMA_GENERIC_RESULT_OK = 0,
    CSORMA_GENERIC_RESULT_ERROR = 9999,
} CSORMA_GENERIC_RESULT;

// ----- shortcuts functions -----
#define csb(b1) csorma_str2_build(b1)
#define csc(b1,b2) csorma_str_con(NULL,b1,b2)
// ----- shortcuts functions -----

typedef struct OrmaDatabase {
    void *user_data;
    void *db;
} OrmaDatabase;

typedef struct csorma_s {
    uint8_t* cur;
    uint32_t l;
    uint8_t n;
    uint8_t* s;
} csorma_s;

typedef void OrmaDatabase_schema_upgrade_callback(uint32_t old_version, uint32_t new_version);

csorma_s *csorma_str2_build(const char *b1);
csorma_s *csorma_str_build(const char *b1, const uint32_t b1_len);
csorma_s *csorma_str_con2(csorma_s *out, csorma_s *append);
csorma_s *csorma_str_con_space(csorma_s *out);
csorma_s *csorma_str_int32t(csorma_s *out, const int32_t append_i);
csorma_s *csorma_str_con(csorma_s *out, const char *b1, const uint32_t b1_len);
void csorma_str_free(csorma_s *s);

const char *csorma_get_version(void);
const char *csorma_get_sqlite_version(void);
const char *csorma_get_sqlcipher_version(void);

OrmaDatabase* OrmaDatabase_init(const uint8_t *directory_name, const uint32_t directory_name_len, 
                                const uint8_t *file_name, const uint32_t file_name_len);

/*
 * returns SQLITE_OK when setting the "key" was ok (this does NOT mean that the "key" was correct, just that the setting of it was OK)
 *         CSORMA_GENERIC_RESULT_ERROR when csorma was not compiled with encryption
 *         any other value when setting the "key" did NOT work
 *
 *         If you specify an incorrect key, you will not get an error message right away.
 *         But the first time you try to access the database you will get an SQLITE_NOTADB error with a message
 *         of "file is encrypted or is not a database".
 *
 */
int OrmaDatabase_key(OrmaDatabase *o, const uint8_t *key, const uint32_t key_len);

void OrmaDatabase_set_schema_upgrade_callback(OrmaDatabase_schema_upgrade_callback *schema_upgrade_callback);
void OrmaDatabase_do_schema_upgrade(const OrmaDatabase *o, uint32_t target_schema_version);

CSORMA_GENERIC_RESULT OrmaDatabase_set_wal_mode(OrmaDatabase *o, const bool use_wal);
void OrmaDatabase_shutdown(OrmaDatabase *o);

CSORMA_GENERIC_RESULT OrmaDatabase_run_multi_sql(const OrmaDatabase *o, const uint8_t *sqltxt);
int64_t OrmaDatabase_run_sql_int64(const OrmaDatabase *o, const uint8_t *sqltxt);

typedef struct OrmaBindvars OrmaBindvars;


// ------ TABLES --------
// ------ TABLES --------
// ------ TABLES --------
__@@@TABLES_RUNTIME_01@@@__
// ------ TABLES --------
// ------ TABLES --------
// ------ TABLES --------

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // C_CSORMA_CSORMA_RUNTIME_H

