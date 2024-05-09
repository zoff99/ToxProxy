
#define CSORMA_LOGGER_MAX_MSG_LEN (2048)

#ifndef CSORMA_MIN_LOGGER_LEVEL
#define CSORMA_MIN_LOGGER_LEVEL CSORMA_LOGGER_LEVEL_WARNING
#endif

typedef enum CSORMA_LOGGER_LEVEL {
    CSORMA_LOGGER_LEVEL_TRACE = 0,
    CSORMA_LOGGER_LEVEL_DEBUG = 1,
    CSORMA_LOGGER_LEVEL_INFO = 2,
    CSORMA_LOGGER_LEVEL_WARNING = 3,
    CSORMA_LOGGER_LEVEL_ERROR = 4,
} CSORMA_LOGGER_LEVEL;

static inline const char *logger_level_name(CSORMA_LOGGER_LEVEL level)
{
    switch (level) {
        case CSORMA_LOGGER_LEVEL_TRACE:
            return "TRACE";

        case CSORMA_LOGGER_LEVEL_DEBUG:
            return "DEBUG";

        case CSORMA_LOGGER_LEVEL_INFO:
            return "INFO";

        case CSORMA_LOGGER_LEVEL_WARNING:
            return "WARNING";

        case CSORMA_LOGGER_LEVEL_ERROR:
            return "ERROR";
    }

    return "<unknown>";
}

void csorma_logger_write(CSORMA_LOGGER_LEVEL level, const char *file, int line, const char *func,
                  const char *format, ...);

#define CSORMA_LOGGER_WRITE_(level, ...)                                            \
    do {                                                                         \
        if (level >= CSORMA_MIN_LOGGER_LEVEL) {                                         \
            csorma_logger_write(level, __FILE__, __LINE__, __func__, __VA_ARGS__); \
        }                                                                        \
    } while (0)

#define CSORMA_LOGGER_TRACE(...)   CSORMA_LOGGER_WRITE_(CSORMA_LOGGER_LEVEL_TRACE, __VA_ARGS__)
#define CSORMA_LOGGER_DEBUG(...)   CSORMA_LOGGER_WRITE_(CSORMA_LOGGER_LEVEL_DEBUG, __VA_ARGS__)
#define CSORMA_LOGGER_INFO(...)    CSORMA_LOGGER_WRITE_(CSORMA_LOGGER_LEVEL_INFO, __VA_ARGS__)
#define CSORMA_LOGGER_WARNING(...) CSORMA_LOGGER_WRITE_(CSORMA_LOGGER_LEVEL_WARNING, __VA_ARGS__)
#define CSORMA_LOGGER_ERROR(...)   CSORMA_LOGGER_WRITE_(CSORMA_LOGGER_LEVEL_ERROR, __VA_ARGS__)
#define CSORMA_LOGGER_ALWAYS(...)   csorma_logger_write(CSORMA_LOGGER_LEVEL_INFO, __FILE__, __LINE__, __func__, __VA_ARGS__)
