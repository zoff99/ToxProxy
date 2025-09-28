#include "csorma_runtime.h"
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

static OrmaDatabase *o = NULL;

void my_custom_schema_upgrade_callback(uint32_t old_version, uint32_t new_version)
{
    printf("STUB: schema upgrade from %d to %d\n", old_version, new_version);
    if (new_version == 1)
    {
        // HINT: do your schema upgrades here
