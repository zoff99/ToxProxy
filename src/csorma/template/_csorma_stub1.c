#include "csorma_runtime.h"
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

int main()
{
    printf("STUB: CSORMA version: %s\n", csorma_get_version());
    printf("STUB: CSORMA SQLite version: %s\n", csorma_get_sqlite_version());
    printf("STUB: CSORMA sqlcipher version: %s\n", csorma_get_sqlcipher_version());
    const char *db_dir = "./";
    const char *db_filename = "stub.db";
    OrmaDatabase *o = OrmaDatabase_init((uint8_t*)db_dir, strlen(db_dir), (uint8_t*)db_filename, strlen(db_filename));

#ifdef ENCRYPT_CSORMA
    // HINT: if `ENCRYPT_CSORMA` is defined then csorma was compiled with `sqlcipher`
    // in case you need to do different things on encrypted databases, you can test for this define.
    printf("STUB: csorma was compiled with sqlcipher encryption\n");
#endif

    // HINT: you can call `OrmaDatabase_key` even when sqlcipher is not used.
    //       then it will return `CSORMA_GENERIC_RESULT_ERROR` and normal unencrypted sqlite is used.
    const char *orma_secret_key = "secret007$%";
    int key_result = OrmaDatabase_key(o, (uint8_t*)orma_secret_key, strlen(orma_secret_key));
    printf("STUB: setting sqlcipher key. result = %d\n", key_result);

    // HINT: set WAL mode for a performance increase
    CSORMA_GENERIC_RESULT res1 = OrmaDatabase_set_wal_mode(o, false);
    printf("STUB: disabling WAL mode. result = %d\n", (int)res1);
