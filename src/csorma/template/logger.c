#include "logger.h"
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

void csorma_logger_write(CSORMA_LOGGER_LEVEL level, const char *file, int line, const char *func,
                  const char *format, ...)
{
    // Only pass the file name, not the entire file path, for privacy reasons.
    // The full path may contain PII of the person compiling toxcore (their
    // username and directory layout).
    const char *filename = strrchr(file, '/');
    file = filename != NULL ? filename + 1 : file;
#if defined(_WIN32) || defined(__CYGWIN__)
    // On Windows, the path separator *may* be a backslash, so we look for that
    // one too.
    const char *windows_filename = strrchr(file, '\\');
    file = windows_filename != NULL ? windows_filename + 1 : file;
#endif

    // Format message
    char msg[(CSORMA_LOGGER_MAX_MSG_LEN)];
    va_list args;
    va_start(args, format);
    vsnprintf(msg, sizeof(msg), format, args);
    va_end(args);

    fprintf(stderr, "CSORMA: %s %s:%d(%s): %s\n", logger_level_name(level), file, line, func, msg);
}
