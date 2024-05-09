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
    const char *db_dir = "./";
    const char *db_filename = "stub.db";
    OrmaDatabase *o = OrmaDatabase_init((uint8_t*)db_dir, strlen(db_dir), (uint8_t*)db_filename, strlen(db_filename));
