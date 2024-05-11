/*
 ============================================================================
 Name        : ToxProxy.c
 Authors     : Thomas Käfer, Zoff
 Copyright   : 2019 - 2024

Zoff sagt: wichtig: erste relay message am 20.08.2019 um 20:31 gesendet und richtig angezeigt.

 This program is free software: you can redistribute it and/or modify
 it under the terms of the GNU Affero General Public License as
 published by the Free Software Foundation, either version 3 of the
 License, or (at your option) any later version.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 GNU Affero General Public License for more details.

 You should have received a copy of the GNU Affero General Public License
 along with this program. If not, see <https://www.gnu.org/licenses/>.

 ============================================================================
 */

#define _GNU_SOURCE

// ----------- version -----------
// ----------- version -----------
#define VERSION_MAJOR 2
#define VERSION_MINOR 0
#define VERSION_PATCH 3
#if defined(__SANITIZE_ADDRESS__)
    static const char global_version_string[] = "2.0.3-ASAN";
#else
    static const char global_version_string[] = "2.0.3";
#endif

// ----------- version -----------
// ----------- version -----------

// define this to write my own tox id to a text file
#define WRITE_MY_TOXID_TO_FILE

// define this to have the log statements also printed to stdout and not only into logfile
// #define LOG2STDOUT

// define this so every run creates a new (timestamped) logfile and doesn't overwrite previous logfiles.
// #define UNIQLOGFILE


#include <ctype.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <getopt.h>
#include <fcntl.h>
#include <assert.h>
#include <limits.h>
#include <stdbool.h>
#include <pthread.h>
#include <signal.h>
#include <time.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/types.h>


#include <sodium/utils.h>

#include "tox/tox.h"
#include "tox/toxutil.h"

#include "sql_tables/gen/csorma_runtime.h"

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

// -------- bin2upper_case_hex (the out "_B2UH_buf" will have a NULL terminator at the end) --------
#define TO_UPPER_HEX_CHAR(val) ((val) < 10 ? (val) + '0' : (val) - 10 + 'A')
#define TO_UPPER_HEX_STRING(buffer, hex_buffer, size) do { \
    for (int32_t i = 0; i < (int32_t)size; i++) { \
        hex_buffer[2*i] = TO_UPPER_HEX_CHAR((buffer[i] >> 4) & 0xF); \
        hex_buffer[2*i + 1] = TO_UPPER_HEX_CHAR(buffer[i] & 0xF); \
    } \
} while(0)
//
//
// HINT: buffer -> const char* input buffer with bytes
//       size   -> length in bytes of the input buffer WITHOUT NULL terminator
//
#define B2UH(buffer, size, _B2UH_buf) do { \
    TO_UPPER_HEX_STRING(buffer, _B2UH_buf, size); \
    _B2UH_buf[2*size] = '\0'; \
} while(0)
// -------- bin2upper_case_hex (the out buffer will have a NULL terminator at the end) --------

// -------- any_case_hex2bin (the in buffer "hex_str" must have a NULL terminator at the end, the out buffer will NOT be NULL terminated) --------
// WARNING: !! if you put garbage in you get garbabe out !!
#define HEX_TO_BYTE_UPPER(hex) ((hex >= 'A' && hex <= 'F') ? (hex - 'A' + 10) : (hex - '0'))
#define HEX_TO_BYTE_LOWER(hex) ((hex >= 'a' && hex <= 'f') ? (hex - 'a' + 10) : (hex - '0'))
#define HEX_TO_BYTE_CASE(hex) ((hex >= 'A' && hex <= 'F') ? (HEX_TO_BYTE_UPPER(hex)) : (HEX_TO_BYTE_LOWER(hex)))
#define H2B(hex_str, _H2B_buf) \
    do { \
        int i; \
        for (i = 0; hex_str[2 * i] && hex_str[2 * i + 1]; ++i) { \
            _H2B_buf[i] = (HEX_TO_BYTE_CASE(hex_str[2 * i]) << 4) + HEX_TO_BYTE_CASE(hex_str[2 * i + 1]); \
        } \
    } while (0)
// WARNING: !! if you put garbage in you get garbabe out !!
// -------- any_case_hex2bin (the in buffer "hex_str" must have a NULL terminator at the end, the out buffer will NOT be NULL terminated) --------


// -------- create a csorma uppercase hex string from bytebuffer statically allocated --------
#define ASSIGN_B2UH_CSB(assign_var, bytebuf, bytebuf_len) do { \
    char x_uhex[2*bytebuf_len + 1]; \
    B2UH(bytebuf, bytebuf_len, x_uhex); \
    assign_var = csb(x_uhex); \
} while(0)
// -------- create a csorma uppercase hex string from bytebuffer statically allocated --------


static char *NOTIFICATION__device_token = NULL;
static const char *NOTIFICATION_GOTIFY_UP_PREFIX = "https://";
static const char *LOV_KEY_PUSHTOKEN = "PUSHTOKEN";

#define NOTI__device_token_min_len 5
#define NOTI__device_token_max_len 300

#define NOTIFICATION_METHOD_NONE 0
#define NOTIFICATION_METHOD_GOTIFY_UP 3

#define NOTIFICATION_METHOD NOTIFICATION_METHOD_GOTIFY_UP

#if NOTIFICATION_METHOD == NOTIFICATION_METHOD_GOTIFY_UP
#include <curl/curl.h>
#endif

typedef struct DHT_node {
    const char *ip;
    uint16_t port;
    const char key_hex[TOX_PUBLIC_KEY_SIZE * 2 + 1];
    unsigned char key_bin[TOX_PUBLIC_KEY_SIZE];
} DHT_node;

typedef enum LOGLEVEL {
    LOGLEVEL_ERROR = 0,
    LOGLEVEL_WARN = 1,
    LOGLEVEL_INFO = 2,
    LOGLEVEL_DEBUG = 9,
} LOGLEVEL;

#define CURRENT_LOG_LEVEL LOGLEVEL_INFO // log everything including and (numerically) below the CURRENT_LOG_LEVEL
#define c_sleep(x) usleep_usec(1000*(x))
#define CLEAR(x) memset(&(x), 0, sizeof(x))


typedef enum CONTROL_PROXY_MESSAGE_TYPE {
    CONTROL_PROXY_MESSAGE_TYPE_FRIEND_PUBKEY_FOR_PROXY = 175,
    CONTROL_PROXY_MESSAGE_TYPE_PROXY_PUBKEY_FOR_FRIEND = 176,
    CONTROL_PROXY_MESSAGE_TYPE_ALL_MESSAGES_SENT = 177,
    CONTROL_PROXY_MESSAGE_TYPE_PROXY_KILL_SWITCH = 178,
    CONTROL_PROXY_MESSAGE_TYPE_NOTIFICATION_TOKEN = 179,
    CONTROL_PROXY_MESSAGE_TYPE_PUSH_URL_FOR_FRIEND = 181
} CONTROL_PROXY_MESSAGE_TYPE;

FILE *logfile = NULL;
#ifndef UNIQLOGFILE
const char *log_filename = "toxblinkenwall.log";
#endif

const char *save_dir = "./db/";
const char *savedata_filename = "./db/savedata.tox";
const char *savedata_tmp_filename = "./db/savedata.tox.tmp";
const char *legacy_masterpubkey_filename = "./db/toxproxymasterpubkey.txt";

const char *dbfilename = "toxproxy.db";


const char *empty_log_message = "empty log message received!";
const char *msgsDir = "./messages";

#ifdef WRITE_MY_TOXID_TO_FILE
const char *my_toxid_filename_txt = "toxid.txt";
const char *my_toxid_filename_txt2 = "./db/toxid.txt";
#endif

const char *shell_cmd__onstart = "./scripts/on_start.sh 2> /dev/null";
const char *shell_cmd__ononline = "./scripts/on_online.sh 2> /dev/null";
const char *shell_cmd__onoffline = "./scripts/on_offline.sh 2> /dev/null";
uint32_t my_last_online_ts = 0;
#define BOOTSTRAP_AFTER_OFFLINE_SECS 30
TOX_CONNECTION my_connection_status = TOX_CONNECTION_NONE;

#define MAX_FILES_IN_ONE_MESSAGE_DIR 2000 // limit MSG files per directory
#define MAX_ANSWER_FILES_IN_ONE_MESSAGE_DIR 2000 // limit ACK files per directory

uint32_t tox_public_key_hex_size = 0; //initialized in main
uint32_t tox_public_key_hex_size_without_null_termin = 0; //initialized in main
uint32_t tox_address_hex_size = 0; //initialized in main
uint32_t tox_address_hex_size_without_null_termin = 0; //initialized in main

const uint32_t tox_group_key_hex_size = TOX_GROUP_CHAT_ID_SIZE * 2 + 1;
const uint32_t tox_group_key_hex_size_without_null_termin = TOX_GROUP_CHAT_ID_SIZE * 2;

int tox_loop_running = 1;
bool masterIsOnline = false;
#define PROXY_PORT_TOR_DEFAULT 9050
int use_tor = 0;

pthread_t notification_thread;
int notification_thread_stop = 1;
int need_send_notification = 0;

OrmaDatabase *o = NULL;

// functions defs ------------
int ping_push_service();
// functions defs ------------

bool file_exists(const char *path)
{
    struct stat s;
    return stat(path, &s) == 0;
}

void openLogFile()
{
// gcc parameter -DUNIQLOGFILE for logging to standardout = console
#ifdef UNIQLOGFILE
    struct timeval tv;
    gettimeofday(&tv, NULL);
    struct tm tm;
    tm = *localtime_r(&tv.tv_sec, &tm);
    const int length = 39; // = length of "ToxProxy_0000-00-00_0000-00,000000.log" + 1 for \0 terminator
    char *uniq_log_filename = calloc(1, length);
    snprintf(uniq_log_filename, length, "ToxProxy_%04d-%02d-%02d_%02d%02d-%02d,%06ld.log", tm.tm_year + 1900, tm.tm_mon + 1,
             tm.tm_mday, tm.tm_hour,
             tm.tm_min, tm.tm_sec, tv.tv_usec);
    logfile = fopen(uniq_log_filename, "wb");
    free(uniq_log_filename);
#else
    logfile = fopen(log_filename, "wb");
#endif

    setvbuf(logfile, NULL, _IOLBF,
            0); // Line buffered, (default is fully buffered) so every logline is instantly visible (and doesn't vanish in a crash situation)
}

#ifdef __MINGW32__
#define dbg2(ignore, ...) do { \
    printf(__VA_ARGS__); \
    printf("\n"); \
} while(0)
#define dbg(...) dbg2(__VA_ARGS__)
#else
void dbg(int level, const char *msg, ...)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    struct tm tm = *localtime(&tv.tv_sec);

    if (msg == NULL || strlen(msg) < 1) {
        // log message is NULL or msg length is 0 or negative
        msg = empty_log_message;
    }

    // 2019-08-03 17:01:04.440494 --> 4+1+2+1+2+1+2+1+2+1+2+1+6 = 26 ; [I] --> 5 ; + msg + \n
    // char buffer[26 + 5 + strlen(msg) + 1]; // = "0000-00-00 00:00:00.000000 [_] msg\n" -- removed extra trailing \0\0.
    const size_t len = 26 + 5 + strlen(msg) + 2;
    char *buffer = calloc(1, len);
    snprintf(buffer, len, "%04d-%02d-%02d %02d:%02d:%02d.%06ld [_] %s\n", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
             tm.tm_hour, tm.tm_min, tm.tm_sec, tv.tv_usec, msg);

    switch (level) {
        case LOGLEVEL_ERROR:
            buffer[28] = 'E';
            break;

        case LOGLEVEL_WARN:
            buffer[28] = 'W';
            break;

        case LOGLEVEL_INFO:
            buffer[28] = 'I';
            break;

        default:
            if (level > 2) {
                buffer[28] = 'D';
            } else {
                buffer[28] = '?';
            }

            break;
    }

    if (level <= CURRENT_LOG_LEVEL)
    {
        va_list ap;

// gcc parameter -DLOG2STDOUT for logging to standardout = console
#ifdef LOG2STDOUT
        va_start(ap, msg);
        vprintf(buffer, ap);
        va_end(ap);
#endif

        if (logfile) {
            va_start(ap, msg);
            vfprintf(logfile, buffer, ap);
            va_end(ap);
        }
    }

    free(buffer);
}
#endif

void tox_log_cb__custom(Tox *UNUSED(tox), TOX_LOG_LEVEL level, const char *file, uint32_t line, const char *func,
                        const char *message, void *UNUSED(user_data))
{
    int log_level = LOGLEVEL_DEBUG;
    if (level == TOX_LOG_LEVEL_TRACE) {log_level = LOGLEVEL_DEBUG;}
    if (level == TOX_LOG_LEVEL_DEBUG) {log_level = LOGLEVEL_DEBUG;}
    if (level == TOX_LOG_LEVEL_INFO) {log_level = LOGLEVEL_INFO;}
    if (level == TOX_LOG_LEVEL_WARNING) {log_level = LOGLEVEL_WARN;}
    if (level == TOX_LOG_LEVEL_ERROR) {log_level = LOGLEVEL_ERROR;}
    dbg(log_level, "ToxCore LogMsg: [%d] %s:%d - %s:%s", (int) level, file, (int) line, func, message);
}

static void shutdown_db()
{
    dbg(LOGLEVEL_INFO, "shutting down db");
    OrmaDatabase_shutdown(o);
    dbg(LOGLEVEL_INFO, "shutting db DONE");
}

static void create_db()
{
    dbg(LOGLEVEL_INFO, "CSORMA version: %s", csorma_get_version());
    dbg(LOGLEVEL_INFO, "CSORMA SQLite version: %s", csorma_get_sqlite_version());
    const char *db_dir = save_dir;
    const char *db_filename = dbfilename;
    o = OrmaDatabase_init((uint8_t*)db_dir, strlen(db_dir), (uint8_t*)db_filename, strlen(db_filename));


    {
    char *sql2 = "CREATE TABLE IF NOT EXISTS \"Group\" ("
    "      \"groupid\" TEXT,    "
    "      \"is_silent\" BOOLEAN,    "
    "      PRIMARY KEY(\"groupid\")    "
    "    );    "
    ;
    dbg(LOGLEVEL_INFO, "creating table: Group");
    CSORMA_GENERIC_RESULT res1 = OrmaDatabase_run_multi_sql(o, (const uint8_t *)sql2);
    dbg(LOGLEVEL_INFO, "res1: %d", res1);
    }
    {
    char *sql2 = "CREATE TABLE IF NOT EXISTS \"Friend\" ("
    "      \"pubkey\" TEXT,    "
    "      \"is_master\" BOOLEAN,    "
    "      \"is_silent\" BOOLEAN,    "
    "      PRIMARY KEY(\"pubkey\")    "
    "    );    "
    ;
    dbg(LOGLEVEL_INFO, "creating table: Friend");
    CSORMA_GENERIC_RESULT res1 = OrmaDatabase_run_multi_sql(o, (const uint8_t *)sql2);
    dbg(LOGLEVEL_INFO, "res1: %d", res1);
    }
    {
    char *sql2 = "CREATE TABLE IF NOT EXISTS \"Lov\" ("
    "      \"key\" TEXT,    "
    "      \"value\" TEXT,    "
    "      PRIMARY KEY(\"key\")    "
    "    );    "
    ;
    dbg(LOGLEVEL_INFO, "creating table: Lov");
    CSORMA_GENERIC_RESULT res1 = OrmaDatabase_run_multi_sql(o, (const uint8_t *)sql2);
    dbg(LOGLEVEL_INFO, "res1: %d", res1);
    }
    {
    char *sql2 = "CREATE TABLE IF NOT EXISTS \"Message\" ("
    "  \"id\" INTEGER,"
    "  \"pubkey\" TEXT,"
    "  \"datahex\" TEXT,"
    "  \"wrappeddatahex\" TEXT,"
    "  \"message_id\" INTEGER,"
    "  \"timstamp_recv\" INTEGER,"
    "  \"message_hashid\" TEXT,"
    "  \"message_sync_hashid\" TEXT,"
    "  \"mtype\" INTEGER,"
    "  PRIMARY KEY(\"id\" AUTOINCREMENT)"
    ");"
    ;
    dbg(LOGLEVEL_INFO, "creating table: Message");
    CSORMA_GENERIC_RESULT res1 = OrmaDatabase_run_multi_sql(o, (const uint8_t *)sql2);
    dbg(LOGLEVEL_INFO, "res1: %d", res1);
    }
    {
    char *sql2 = "CREATE TABLE IF NOT EXISTS \"Group_message\" ("
    "  \"id\" INTEGER,"
    "  \"groupid\" TEXT,"
    "  \"peerpubkey\" TEXT,"
    "  \"datahex\" TEXT,"
    "  \"wrappeddatahex\" TEXT,"
    "  \"message_id\" INTEGER,"
    "  \"timstamp_recv\" INTEGER,"
    "  \"message_hashid\" TEXT,"
    "  \"message_sync_hashid\" TEXT,"
    "  \"mtype\" INTEGER,"
    "  PRIMARY KEY(\"id\" AUTOINCREMENT)"
    ");"
    ;
    dbg(LOGLEVEL_INFO, "creating table: Group_message");
    CSORMA_GENERIC_RESULT res1 = OrmaDatabase_run_multi_sql(o, (const uint8_t *)sql2);
    dbg(LOGLEVEL_INFO, "res1: %d", res1);
    }
    {
    char *sql2 = "CREATE TABLE IF NOT EXISTS \"Self\" ("
    "  \"toxid\" TEXT,"
    "  \"master_pubkey\" TEXT,"
    "  PRIMARY KEY(\"toxid\")"
    ");"
    ;
    dbg(LOGLEVEL_INFO, "creating table: Self");
    CSORMA_GENERIC_RESULT res1 = OrmaDatabase_run_multi_sql(o, (const uint8_t *)sql2);
    dbg(LOGLEVEL_INFO, "res1: %d", res1);
    }

    {
    char *sql2 = ""
    "CREATE INDEX IF NOT EXISTS \"index_timstamp_recv_on_Message\" ON Message (timstamp_recv);"
    "CREATE INDEX IF NOT EXISTS \"index_timstamp_recv_on_Group_message\" ON Group_message (timstamp_recv);"
    "CREATE INDEX IF NOT EXISTS \"index_message_hashid_on_Message\" ON Message (message_hashid);"
    "CREATE INDEX IF NOT EXISTS \"index_message_hashid_on_Group_message\" ON Group_message (message_hashid);"
    ;
    dbg(LOGLEVEL_INFO, "creating indexes");
    CSORMA_GENERIC_RESULT res1 = OrmaDatabase_run_multi_sql(o, (const uint8_t *)sql2);
    dbg(LOGLEVEL_INFO, "res1: %d", res1);
    }
}

static void add_group_to_db(const char *groupidhex, const uint32_t len)
{
    Group *g = orma_new_Group(o->db);
    g->groupid = csc(groupidhex, len);
    g->is_silent = false;
    int64_t inserted_id = orma_insertIntoGroup(g);
    if (inserted_id > -1)
    {
        dbg(LOGLEVEL_INFO, "added group to db, inserted id: %lld", (long long)inserted_id);
    }
    orma_free_Group(g);
}

static void add_friend_to_db(const char *pubkeyhex, const uint32_t len, const bool is_master)
{
    Friend *f = orma_new_Friend(o->db);
    f->pubkey = csc(pubkeyhex, len);
    f->is_master = is_master;
    f->is_silent = false;
    int64_t inserted_id = orma_insertIntoFriend(f);
    if (inserted_id > -1)
    {
        dbg(LOGLEVEL_INFO, "added friend to db, inserted id: %lld", (long long)inserted_id);
    }
    orma_free_Friend(f);
}

time_t get_unix_time(void)
{
    return time(NULL);
}

void usleep_usec(uint64_t usec)
{
    struct timespec ts;
    ts.tv_sec = usec / 1000000;
    ts.tv_nsec = (usec % 1000000) * 1000;
    nanosleep(&ts, NULL);
}

void bin2upHex(const uint8_t *bin, uint32_t bin_size, char *hex, uint32_t hex_size)
{
    sodium_bin2hex(hex, hex_size, bin, bin_size);

    for (size_t i = 0; i < hex_size - 1; i++) {
        hex[i] = toupper(hex[i]);
    }
}

int hex_string_to_bin(const char *hex_string, size_t hex_len, char *output, size_t output_size)
{
    if (output_size == 0 || hex_len != output_size * 2) {
        return -1;
    }

    for (size_t i = 0; i < output_size; ++i) {
        sscanf(hex_string, "%2hhx", (unsigned char *) &output[i]);
        hex_string += 2;
    }

    return 0;
}

unsigned int char_to_int(char c)
{
    if (c >= '0' && c <= '9') {
        return (uint8_t)c - '0';
    }

    if (c >= 'A' && c <= 'F') {
        return 10 + (uint8_t)c - 'A';
    }

    if (c >= 'a' && c <= 'f') {
        return 10 + (uint8_t)c - 'a';
    }

    return -1;
}

void on_start()
{
    char *cmd_str = calloc(1, 1000);
    snprintf(cmd_str, 999, "%s", shell_cmd__onstart);

    if (system(cmd_str)) {}

    free(cmd_str);
}

void on_online()
{
    char *cmd_str = calloc(1, 1000);
    snprintf(cmd_str, 999, "%s", shell_cmd__ononline);

    if (system(cmd_str)) {}

    free(cmd_str);
}

void on_offline()
{
    char *cmd_str = calloc(1, 1000);
    snprintf(cmd_str, 999, "%s", shell_cmd__onoffline);

    if (system(cmd_str)) {}

    free(cmd_str);

    // if we go offline, immediately bootstrap again. maybe we can go online faster
    // set last online timestamp into the past
    uint32_t my_last_online_ts_ = (uint32_t)get_unix_time();

    if (my_last_online_ts_ > (BOOTSTRAP_AFTER_OFFLINE_SECS * 1000)) {
        // give 2 seconds to go online by itself, otherwise we bootstrap again
        my_last_online_ts = my_last_online_ts_ - ((BOOTSTRAP_AFTER_OFFLINE_SECS - 2) * 1000);
    }
}

void killSwitch() __attribute__((noreturn));

void killSwitch()
{
    dbg(LOGLEVEL_DEBUG, "got killSwitch command, deleting all data");
    unlink(savedata_filename);
    dbg(LOGLEVEL_WARN, "todo implement deleting messages");
    tox_loop_running = 0;
    exit(0);
}

void sigint_handler(int signo)
{
    if (signo == SIGINT) {
        fprintf(stderr, "received SIGINT, pid=%d\n", getpid());
        tox_loop_running = 0;
    }
}

void updateToxSavedata(const Tox *tox)
{
    size_t size = tox_get_savedata_size(tox);
    uint8_t *savedata = calloc(1, size);
    tox_get_savedata(tox, savedata);

    FILE *f = fopen(savedata_tmp_filename, "wb");
    fwrite(savedata, size, 1, f);
    fclose(f);

    rename(savedata_tmp_filename, savedata_filename);
    free(savedata);
}

uint8_t *get_friend_name(Tox *tox, uint32_t friend_number)
{
    TOX_ERR_FRIEND_QUERY error;
    int name_size = tox_friend_get_name_size(tox, friend_number, &error);
    if (name_size > 0)
    {
        uint8_t *f_name = calloc(1, name_size + 1);
        if (f_name)
        {
            bool res = tox_friend_get_name(tox, friend_number, f_name, &error);
            if (res == true)
            {
                return f_name;
            }
            free(f_name);
        }
    }

    return NULL;
}

Tox *openTox()
{
    Tox *tox = NULL;

    struct Tox_Options options;

    tox_options_default(&options);

    // ----- set options ------
    options.ipv6_enabled = true;
    options.local_discovery_enabled = true;
    options.hole_punching_enabled = true;
    options.udp_enabled = true;
    options.tcp_port = 0; // disable tcp relay function!
    // ----- set options ------

    if (use_tor == 0)
    {
        options.udp_enabled = true; // UDP mode
        dbg(LOGLEVEL_INFO, "setting UDP mode");
    }
    else
    {
        options.udp_enabled = false; // TCP mode
        dbg(LOGLEVEL_INFO, "setting TCP mode");
    }

    if (use_tor == 1)
    {
        dbg(LOGLEVEL_INFO, "setting Tor Relay mode");
        options.udp_enabled = false; // TCP mode
        dbg(LOGLEVEL_INFO, "setting TCP mode");
        const char *proxy_host = "127.0.0.1";
        dbg(LOGLEVEL_INFO, "setting proxy_host %s", proxy_host);
        uint16_t proxy_port = PROXY_PORT_TOR_DEFAULT;
        dbg(LOGLEVEL_INFO, "setting proxy_port %d", (int)proxy_port);
        options.proxy_type = TOX_PROXY_TYPE_SOCKS5;
        options.proxy_host = proxy_host;
        options.proxy_port = proxy_port;
    }
    else
    {
        options.proxy_type = TOX_PROXY_TYPE_NONE;
    }

    // set our own handler for c-toxcore logging messages!!
    options.log_callback = tox_log_cb__custom;

    FILE *f = fopen(savedata_filename, "rb");
    uint8_t *savedata = NULL;

    if (f) {
        fseek(f, 0, SEEK_END);
        size_t savedataSize = ftell(f);
        fseek(f, 0, SEEK_SET);

        savedata = malloc(savedataSize);
        size_t ret = fread(savedata, savedataSize, 1, f);

        // TODO: handle ret return vlaue here!
        if (ret) {
            // ------
        }

        fclose(f);

        options.savedata_type = TOX_SAVEDATA_TYPE_TOX_SAVE;
        options.savedata_data = savedata;
        options.savedata_length = savedataSize;
    }

#ifdef TOX_HAVE_TOXUTIL
    tox = tox_utils_new(&options, NULL);
#else
    tox = tox_new(&options, NULL);
#endif

    free(savedata);
    return tox;
}

void shuffle(int *array, size_t n)
{
#ifndef __MINGW32__
    struct timeval tv;
    gettimeofday(&tv, NULL);
    int usec = tv.tv_usec;
    srand48(usec);

    if (n > 1) {
        size_t i;

        for (i = n - 1; i > 0; i--) {
            size_t j = (unsigned int)(drand48() * (i + 1));
            int t = array[j];
            array[j] = array[i];
            array[i] = t;
        }
    }
#endif
}

void bootstap_nodes(Tox *tox, DHT_node nodes[], int number_of_nodes, int add_as_tcp_relay)
{
    int random_order_nodenums[number_of_nodes];

    for (size_t j = 0; (int)j < (int)number_of_nodes; j++) {
        random_order_nodenums[j] = (int)j;
    }

    shuffle(random_order_nodenums, number_of_nodes);

    for (size_t j = 0; (int)j < (int)number_of_nodes; j++) {
        size_t i = (size_t)random_order_nodenums[j];
        bool res = sodium_hex2bin(nodes[i].key_bin, sizeof(nodes[i].key_bin),
                                  nodes[i].key_hex, sizeof(nodes[i].key_hex) - 1, NULL, NULL, NULL);
        dbg(LOGLEVEL_DEBUG, "bootstap_nodes - sodium_hex2bin:res=%d", res);

        TOX_ERR_BOOTSTRAP error;
        res = tox_bootstrap(tox, nodes[i].ip, nodes[i].port, nodes[i].key_bin, &error);

        if (res != true) {
            if (error == TOX_ERR_BOOTSTRAP_OK) {
              dbg(LOGLEVEL_DEBUG, "bootstrap:%s %d [FALSE]res=TOX_ERR_BOOTSTRAP_OK", nodes[i].ip, nodes[i].port);
            } else if (error == TOX_ERR_BOOTSTRAP_NULL) {
              dbg(LOGLEVEL_DEBUG, "bootstrap:%s %d [FALSE]res=TOX_ERR_BOOTSTRAP_NULL", nodes[i].ip, nodes[i].port);
            } else if (error == TOX_ERR_BOOTSTRAP_BAD_HOST) {
              dbg(LOGLEVEL_DEBUG, "bootstrap:%s %d [FALSE]res=TOX_ERR_BOOTSTRAP_BAD_HOST", nodes[i].ip, nodes[i].port);
            } else if (error == TOX_ERR_BOOTSTRAP_BAD_PORT) {
              dbg(LOGLEVEL_DEBUG, "bootstrap:%s %d [FALSE]res=TOX_ERR_BOOTSTRAP_BAD_PORT", nodes[i].ip, nodes[i].port);
            }
        } else {
          dbg(LOGLEVEL_DEBUG, "bootstrap:%s %d [TRUE] res=%d", nodes[i].ip, nodes[i].port, res);
        }

        if (add_as_tcp_relay == 1) {
            TOX_ERR_BOOTSTRAP error;
            res = tox_add_tcp_relay(tox, nodes[i].ip, nodes[i].port, nodes[i].key_bin, &error); // use also as TCP relay

            if (res != true) {
                if (error == TOX_ERR_BOOTSTRAP_OK) {
                  dbg(LOGLEVEL_DEBUG, "add_tcp_relay:%s %d [FALSE] res=TOX_ERR_BOOTSTRAP_OK", nodes[i].ip, nodes[i].port);
                } else if (error == TOX_ERR_BOOTSTRAP_NULL) {
                  dbg(LOGLEVEL_DEBUG, "add_tcp_relay:%s %d [FALSE] res=TOX_ERR_BOOTSTRAP_NULL", nodes[i].ip, nodes[i].port);
                } else if (error == TOX_ERR_BOOTSTRAP_BAD_HOST) {
                  dbg(LOGLEVEL_DEBUG, "add_tcp_relay:%s %d [FALSE] res=TOX_ERR_BOOTSTRAP_BAD_HOST", nodes[i].ip, nodes[i].port);
                } else if (error == TOX_ERR_BOOTSTRAP_BAD_PORT) {
                  dbg(LOGLEVEL_DEBUG, "add_tcp_relay:%s %d [FALSE] res=TOX_ERR_BOOTSTRAP_BAD_PORT", nodes[i].ip, nodes[i].port);
                }
            } else {
              dbg(LOGLEVEL_DEBUG, "add_tcp_relay:%s %d [TRUE] res=%d", nodes[i].ip, nodes[i].port, res);
            }
        } else {
            dbg(LOGLEVEL_DEBUG, "Not adding any TCP relays");
        }
    }
}

void bootstrap(Tox *tox)
{
    // use these nodes as bootstrap nodes
    DHT_node nodes_bootstrap_nodes[] =
    {

        {"144.217.167.73"                           ,    33445, "7E5668E0EE09E19F320AD47902419331FFEE147BB3606769CFBE921A2A2FD34C", {0}},
        {"tox.abilinski.com"                        ,    33445, "10C00EB250C3233E343E2AEBA07115A5C28920E9C8D29492F6D00B29049EDC7E", {0}},
        {"tox.kurnevsky.net"                        ,    33445, "82EF82BA33445A1F91A7DB27189ECFC0C013E06E3DA71F588ED692BED625EC23", {0}},
        {"2a03:b0c0:0:1010::4c:5001"                ,    33445, "82EF82BA33445A1F91A7DB27189ECFC0C013E06E3DA71F588ED692BED625EC23", {0}},
        {"205.185.115.131"                          ,    53   , "3091C6BEB2A993F1C6300C16549FABA67098FF3D62C6D253828B531470B53D68", {0}},
        {"tox2.abilinski.com"                       ,    33445, "7A6098B590BDC73F9723FC59F82B3F9085A64D1B213AAF8E610FD351930D052D", {0}},
        {"2604:180:1:4ab::2"                        ,    33445, "7A6098B590BDC73F9723FC59F82B3F9085A64D1B213AAF8E610FD351930D052D", {0}},
        {"46.101.197.175"                           ,    33445, "CD133B521159541FB1D326DE9850F5E56A6C724B5B8E5EB5CD8D950408E95707", {0}},
        {"2a03:b0c0:3:d0::ac:5001"                  ,    33445, "CD133B521159541FB1D326DE9850F5E56A6C724B5B8E5EB5CD8D950408E95707", {0}},
        {"tox1.mf-net.eu"                           ,    33445, "B3E5FA80DC8EBD1149AD2AB35ED8B85BD546DEDE261CA593234C619249419506", {0}},
        {"2a01:4f8:c2c:89f7::1"                     ,    33445, "B3E5FA80DC8EBD1149AD2AB35ED8B85BD546DEDE261CA593234C619249419506", {0}},
        {"tox4.plastiras.org"                       ,    33445, "836D1DA2BE12FE0E669334E437BE3FB02806F1528C2B2782113E0910C7711409", {0}},
        {"5.19.249.240"                             ,    38296, "DA98A4C0CD7473A133E115FEA2EBDAEEA2EF4F79FD69325FC070DA4DE4BA3238", {0}},
        {"188.225.9.167"                            ,    33445, "1911341A83E02503AB1FD6561BD64AF3A9D6C3F12B5FBB656976B2E678644A67", {0}},
        {"209:dead:ded:4991:49f3:b6c0:9869:3019"    ,    33445, "1911341A83E02503AB1FD6561BD64AF3A9D6C3F12B5FBB656976B2E678644A67", {0}},
        {"3.0.24.15"                                ,    33445, "E20ABCF38CDBFFD7D04B29C956B33F7B27A3BB7AF0618101617B036E4AEA402D", {0}},
        {"tox3.plastiras.org"                       ,    33445, "4B031C96673B6FF123269FF18F2847E1909A8A04642BBECD0189AC8AEEADAF64", {0}},
        {"2a02:587:4c10:ea95:d375:33a:ace3:c0a0"    ,    33445, "4B031C96673B6FF123269FF18F2847E1909A8A04642BBECD0189AC8AEEADAF64", {0}},
        {"104.225.141.59"                           ,    43334, "933BA20B2E258B4C0D475B6DECE90C7E827FE83EFA9655414E7841251B19A72C", {0}},
        {"139.162.110.188"                          ,    33445, "F76A11284547163889DDC89A7738CF271797BF5E5E220643E97AD3C7E7903D55", {0}},
        {"2400:8902::f03c:93ff:fe69:bf77"           ,    33445, "F76A11284547163889DDC89A7738CF271797BF5E5E220643E97AD3C7E7903D55", {0}},
        {"tox2.mf-net.eu"                           ,    33445, "70EA214FDE161E7432530605213F18F7427DC773E276B3E317A07531F548545F", {0}},
        {"2a01:4f8:c012:cb9::"                      ,    33445, "70EA214FDE161E7432530605213F18F7427DC773E276B3E317A07531F548545F", {0}},
        {"172.105.109.31"                           ,    33445, "D46E97CF995DC1820B92B7D899E152A217D36ABE22730FEA4B6BF1BFC06C617C", {0}},
        {"2600:3c04::f03c:92ff:fe30:5df"            ,    33445, "D46E97CF995DC1820B92B7D899E152A217D36ABE22730FEA4B6BF1BFC06C617C", {0}},
        {"91.146.66.26"                             ,    33445, "B5E7DAC610DBDE55F359C7F8690B294C8E4FCEC4385DE9525DBFA5523EAD9D53", {0}},
        {"tox2.plastiras.org"                       ,    33445, "B6626D386BE7E3ACA107B46F48A5C4D522D29281750D44A0CBA6A2721E79C951", {0}},
        {"2605:6400:30:ea2a:cef4:520c:f4ad:923b"    ,    33445, "B6626D386BE7E3ACA107B46F48A5C4D522D29281750D44A0CBA6A2721E79C951", {0}},
        {"172.104.215.182"                          ,    33445, "DA2BD927E01CD05EBCC2574EBE5BEBB10FF59AE0B2105A7D1E2B40E49BB20239", {0}},
        {"2600:3c03::f03c:93ff:fe7f:6096"           ,    33445, "DA2BD927E01CD05EBCC2574EBE5BEBB10FF59AE0B2105A7D1E2B40E49BB20239", {0}},
        {"tox.initramfs.io"                         ,    33445, "3F0A45A268367C1BEA652F258C85F4A66DA76BCAA667A49E770BCC4917AB6A25", {0}},
        {"2001:b011:4002:1edf::b"                   ,    33445, "3F0A45A268367C1BEA652F258C85F4A66DA76BCAA667A49E770BCC4917AB6A25", {0}},
        {"tox.plastiras.org"                        ,    33445, "8E8B63299B3D520FB377FE5100E65E3322F7AE5B20A0ACED2981769FC5B43725", {0}},
        {"2605:6400:30:f7f4:c24:f413:e44d:a91f"     ,    33445, "8E8B63299B3D520FB377FE5100E65E3322F7AE5B20A0ACED2981769FC5B43725", {0}},
        {"188.214.122.30"                           ,    33445, "2A9F7A620581D5D1B09B004624559211C5ED3D1D712E8066ACDB0896A7335705", {0}},
        {"194.36.190.71"                            ,    33445, "99E8460035E45C0A6B6DC2C02B14440F7F876518E9D054D028209B5669827645", {0}},
        {"62.183.96.32"                             ,    33445, "52BD37D53357701CB9C69ABA81E7741C5F14105523C89153A770D73F434AC473", {0}},
        {"141.11.229.155"                           ,    33445, "1FD96DF8DCAC4A95C117B460F23EB740C8FBA60DE89BE7B45136790B8E3D4B63", {0}},
        {"43.198.227.166"                           ,    33445, "AD13AB0D434BCE6C83FE2649237183964AE3341D0AFB3BE1694B18505E4E135E", {0}},
        {"95.181.230.108"                           ,    33445, "B5FFECB4E4C26409EBB88DB35793E7B39BFA3BA12AC04C096950CB842E3E130A", {0}},
        {"2a03:c980:db:5d::"                        ,    33445, "B5FFECB4E4C26409EBB88DB35793E7B39BFA3BA12AC04C096950CB842E3E130A", {0}},

    };

    // ================
    // ================

    // use these nodes as tcp-relays
    DHT_node nodes_tcp_relays[] =
    {

        {"144.217.167.73"                           ,    33445, "7E5668E0EE09E19F320AD47902419331FFEE147BB3606769CFBE921A2A2FD34C", {0}},
        {"144.217.167.73"                           ,    3389 , "7E5668E0EE09E19F320AD47902419331FFEE147BB3606769CFBE921A2A2FD34C", {0}},
        {"tox.abilinski.com"                        ,    33445, "10C00EB250C3233E343E2AEBA07115A5C28920E9C8D29492F6D00B29049EDC7E", {0}},
        {"205.185.115.131"                          ,    33445, "3091C6BEB2A993F1C6300C16549FABA67098FF3D62C6D253828B531470B53D68", {0}},
        {"205.185.115.131"                          ,    443  , "3091C6BEB2A993F1C6300C16549FABA67098FF3D62C6D253828B531470B53D68", {0}},
        {"205.185.115.131"                          ,    53   , "3091C6BEB2A993F1C6300C16549FABA67098FF3D62C6D253828B531470B53D68", {0}},
        {"205.185.115.131"                          ,    3389 , "3091C6BEB2A993F1C6300C16549FABA67098FF3D62C6D253828B531470B53D68", {0}},
        {"tox2.abilinski.com"                       ,    33445, "7A6098B590BDC73F9723FC59F82B3F9085A64D1B213AAF8E610FD351930D052D", {0}},
        {"2604:180:1:4ab::2"                        ,    33445, "7A6098B590BDC73F9723FC59F82B3F9085A64D1B213AAF8E610FD351930D052D", {0}},
        {"46.101.197.175"                           ,    33445, "CD133B521159541FB1D326DE9850F5E56A6C724B5B8E5EB5CD8D950408E95707", {0}},
        {"2a03:b0c0:3:d0::ac:5001"                  ,    33445, "CD133B521159541FB1D326DE9850F5E56A6C724B5B8E5EB5CD8D950408E95707", {0}},
        {"46.101.197.175"                           ,    3389 , "CD133B521159541FB1D326DE9850F5E56A6C724B5B8E5EB5CD8D950408E95707", {0}},
        {"2a03:b0c0:3:d0::ac:5001"                  ,    3389 , "CD133B521159541FB1D326DE9850F5E56A6C724B5B8E5EB5CD8D950408E95707", {0}},
        {"tox1.mf-net.eu"                           ,    3389 , "B3E5FA80DC8EBD1149AD2AB35ED8B85BD546DEDE261CA593234C619249419506", {0}},
        {"2a01:4f8:c2c:89f7::1"                     ,    3389 , "B3E5FA80DC8EBD1149AD2AB35ED8B85BD546DEDE261CA593234C619249419506", {0}},
        {"tox1.mf-net.eu"                           ,    33445, "B3E5FA80DC8EBD1149AD2AB35ED8B85BD546DEDE261CA593234C619249419506", {0}},
        {"2a01:4f8:c2c:89f7::1"                     ,    33445, "B3E5FA80DC8EBD1149AD2AB35ED8B85BD546DEDE261CA593234C619249419506", {0}},
        {"tox4.plastiras.org"                       ,    33445, "836D1DA2BE12FE0E669334E437BE3FB02806F1528C2B2782113E0910C7711409", {0}},
        {"tox4.plastiras.org"                       ,    3389 , "836D1DA2BE12FE0E669334E437BE3FB02806F1528C2B2782113E0910C7711409", {0}},
        {"tox4.plastiras.org"                       ,    443  , "836D1DA2BE12FE0E669334E437BE3FB02806F1528C2B2782113E0910C7711409", {0}},
        {"5.19.249.240"                             ,    3389 , "DA98A4C0CD7473A133E115FEA2EBDAEEA2EF4F79FD69325FC070DA4DE4BA3238", {0}},
        {"5.19.249.240"                             ,    38296, "DA98A4C0CD7473A133E115FEA2EBDAEEA2EF4F79FD69325FC070DA4DE4BA3238", {0}},
        {"188.225.9.167"                            ,    33445, "1911341A83E02503AB1FD6561BD64AF3A9D6C3F12B5FBB656976B2E678644A67", {0}},
        {"209:dead:ded:4991:49f3:b6c0:9869:3019"    ,    33445, "1911341A83E02503AB1FD6561BD64AF3A9D6C3F12B5FBB656976B2E678644A67", {0}},
        {"188.225.9.167"                            ,    3389 , "1911341A83E02503AB1FD6561BD64AF3A9D6C3F12B5FBB656976B2E678644A67", {0}},
        {"209:dead:ded:4991:49f3:b6c0:9869:3019"    ,    3389 , "1911341A83E02503AB1FD6561BD64AF3A9D6C3F12B5FBB656976B2E678644A67", {0}},
        {"3.0.24.15"                                ,    3389 , "E20ABCF38CDBFFD7D04B29C956B33F7B27A3BB7AF0618101617B036E4AEA402D", {0}},
        {"3.0.24.15"                                ,    33445, "E20ABCF38CDBFFD7D04B29C956B33F7B27A3BB7AF0618101617B036E4AEA402D", {0}},
        {"tox3.plastiras.org"                       ,    33445, "4B031C96673B6FF123269FF18F2847E1909A8A04642BBECD0189AC8AEEADAF64", {0}},
        {"2a02:587:4c10:ea95:d375:33a:ace3:c0a0"    ,    33445, "4B031C96673B6FF123269FF18F2847E1909A8A04642BBECD0189AC8AEEADAF64", {0}},
        {"104.225.141.59"                           ,    3389 , "933BA20B2E258B4C0D475B6DECE90C7E827FE83EFA9655414E7841251B19A72C", {0}},
        {"104.225.141.59"                           ,    33445, "933BA20B2E258B4C0D475B6DECE90C7E827FE83EFA9655414E7841251B19A72C", {0}},
        {"139.162.110.188"                          ,    3389 , "F76A11284547163889DDC89A7738CF271797BF5E5E220643E97AD3C7E7903D55", {0}},
        {"2400:8902::f03c:93ff:fe69:bf77"           ,    3389 , "F76A11284547163889DDC89A7738CF271797BF5E5E220643E97AD3C7E7903D55", {0}},
        {"139.162.110.188"                          ,    443  , "F76A11284547163889DDC89A7738CF271797BF5E5E220643E97AD3C7E7903D55", {0}},
        {"2400:8902::f03c:93ff:fe69:bf77"           ,    443  , "F76A11284547163889DDC89A7738CF271797BF5E5E220643E97AD3C7E7903D55", {0}},
        {"139.162.110.188"                          ,    33445, "F76A11284547163889DDC89A7738CF271797BF5E5E220643E97AD3C7E7903D55", {0}},
        {"2400:8902::f03c:93ff:fe69:bf77"           ,    33445, "F76A11284547163889DDC89A7738CF271797BF5E5E220643E97AD3C7E7903D55", {0}},
        {"tox2.mf-net.eu"                           ,    3389 , "70EA214FDE161E7432530605213F18F7427DC773E276B3E317A07531F548545F", {0}},
        {"2a01:4f8:c012:cb9::"                      ,    3389 , "70EA214FDE161E7432530605213F18F7427DC773E276B3E317A07531F548545F", {0}},
        {"tox2.mf-net.eu"                           ,    33445, "70EA214FDE161E7432530605213F18F7427DC773E276B3E317A07531F548545F", {0}},
        {"2a01:4f8:c012:cb9::"                      ,    33445, "70EA214FDE161E7432530605213F18F7427DC773E276B3E317A07531F548545F", {0}},
        {"172.105.109.31"                           ,    33445, "D46E97CF995DC1820B92B7D899E152A217D36ABE22730FEA4B6BF1BFC06C617C", {0}},
        {"2600:3c04::f03c:92ff:fe30:5df"            ,    33445, "D46E97CF995DC1820B92B7D899E152A217D36ABE22730FEA4B6BF1BFC06C617C", {0}},
        {"tox2.plastiras.org"                       ,    33445, "B6626D386BE7E3ACA107B46F48A5C4D522D29281750D44A0CBA6A2721E79C951", {0}},
        {"2605:6400:30:ea2a:cef4:520c:f4ad:923b"    ,    33445, "B6626D386BE7E3ACA107B46F48A5C4D522D29281750D44A0CBA6A2721E79C951", {0}},
        {"tox2.plastiras.org"                       ,    3389 , "B6626D386BE7E3ACA107B46F48A5C4D522D29281750D44A0CBA6A2721E79C951", {0}},
        {"2605:6400:30:ea2a:cef4:520c:f4ad:923b"    ,    3389 , "B6626D386BE7E3ACA107B46F48A5C4D522D29281750D44A0CBA6A2721E79C951", {0}},
        {"172.104.215.182"                          ,    33445, "DA2BD927E01CD05EBCC2574EBE5BEBB10FF59AE0B2105A7D1E2B40E49BB20239", {0}},
        {"2600:3c03::f03c:93ff:fe7f:6096"           ,    33445, "DA2BD927E01CD05EBCC2574EBE5BEBB10FF59AE0B2105A7D1E2B40E49BB20239", {0}},
        {"172.104.215.182"                          ,    3389 , "DA2BD927E01CD05EBCC2574EBE5BEBB10FF59AE0B2105A7D1E2B40E49BB20239", {0}},
        {"2600:3c03::f03c:93ff:fe7f:6096"           ,    3389 , "DA2BD927E01CD05EBCC2574EBE5BEBB10FF59AE0B2105A7D1E2B40E49BB20239", {0}},
        {"172.104.215.182"                          ,    443  , "DA2BD927E01CD05EBCC2574EBE5BEBB10FF59AE0B2105A7D1E2B40E49BB20239", {0}},
        {"2600:3c03::f03c:93ff:fe7f:6096"           ,    443  , "DA2BD927E01CD05EBCC2574EBE5BEBB10FF59AE0B2105A7D1E2B40E49BB20239", {0}},
        {"tox.initramfs.io"                         ,    3389 , "3F0A45A268367C1BEA652F258C85F4A66DA76BCAA667A49E770BCC4917AB6A25", {0}},
        {"2001:b011:4002:1edf::b"                   ,    3389 , "3F0A45A268367C1BEA652F258C85F4A66DA76BCAA667A49E770BCC4917AB6A25", {0}},
        {"tox.initramfs.io"                         ,    33445, "3F0A45A268367C1BEA652F258C85F4A66DA76BCAA667A49E770BCC4917AB6A25", {0}},
        {"2001:b011:4002:1edf::b"                   ,    33445, "3F0A45A268367C1BEA652F258C85F4A66DA76BCAA667A49E770BCC4917AB6A25", {0}},
        {"tox.plastiras.org"                        ,    443  , "8E8B63299B3D520FB377FE5100E65E3322F7AE5B20A0ACED2981769FC5B43725", {0}},
        {"2605:6400:30:f7f4:c24:f413:e44d:a91f"     ,    443  , "8E8B63299B3D520FB377FE5100E65E3322F7AE5B20A0ACED2981769FC5B43725", {0}},
        {"tox.plastiras.org"                        ,    33445, "8E8B63299B3D520FB377FE5100E65E3322F7AE5B20A0ACED2981769FC5B43725", {0}},
        {"2605:6400:30:f7f4:c24:f413:e44d:a91f"     ,    33445, "8E8B63299B3D520FB377FE5100E65E3322F7AE5B20A0ACED2981769FC5B43725", {0}},
        {"188.214.122.30"                           ,    33445, "2A9F7A620581D5D1B09B004624559211C5ED3D1D712E8066ACDB0896A7335705", {0}},
        {"188.214.122.30"                           ,    3389 , "2A9F7A620581D5D1B09B004624559211C5ED3D1D712E8066ACDB0896A7335705", {0}},
        {"194.36.190.71"                            ,    33445, "99E8460035E45C0A6B6DC2C02B14440F7F876518E9D054D028209B5669827645", {0}},
        {"62.183.96.32"                             ,    33445, "52BD37D53357701CB9C69ABA81E7741C5F14105523C89153A770D73F434AC473", {0}},
        {"141.11.229.155"                           ,    33445, "1FD96DF8DCAC4A95C117B460F23EB740C8FBA60DE89BE7B45136790B8E3D4B63", {0}},
        {"141.11.229.155"                           ,    3389 , "1FD96DF8DCAC4A95C117B460F23EB740C8FBA60DE89BE7B45136790B8E3D4B63", {0}},
        {"43.198.227.166"                           ,    3389 , "AD13AB0D434BCE6C83FE2649237183964AE3341D0AFB3BE1694B18505E4E135E", {0}},
        {"43.198.227.166"                           ,    33445, "AD13AB0D434BCE6C83FE2649237183964AE3341D0AFB3BE1694B18505E4E135E", {0}},
        {"95.181.230.108"                           ,    33445, "B5FFECB4E4C26409EBB88DB35793E7B39BFA3BA12AC04C096950CB842E3E130A", {0}},
        {"2a03:c980:db:5d::"                        ,    33445, "B5FFECB4E4C26409EBB88DB35793E7B39BFA3BA12AC04C096950CB842E3E130A", {0}},
        {"2607:f130:0:f8::4c85:a645"                ,    33445, "8AFE1FC6426E5B77AB80318ED64F5F76341695B9FB47AB8AC9537BF5EE9E9D29", {0}},
        {"2607:f130:0:f8::4c85:a645"                ,    3389 , "8AFE1FC6426E5B77AB80318ED64F5F76341695B9FB47AB8AC9537BF5EE9E9D29", {0}},

    };
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wall"

    // bootstrap nodes
    bootstap_nodes(tox, nodes_bootstrap_nodes, (int)(sizeof(nodes_bootstrap_nodes) / sizeof(DHT_node)), 0);

    // tcp relay nodes
    bootstap_nodes(tox, nodes_tcp_relays, (int)(sizeof(nodes_tcp_relays) / sizeof(DHT_node)), 1);
#pragma GCC diagnostic pop
}

void add_master(const char *public_key_hex)
{
    // mastersql
    Self *s = orma_updateSelf(o->db);
    int64_t affected_rows3 = s->master_pubkeySet(s, csb(public_key_hex))->execute(s);
    if (affected_rows3 < 1)
    {
        dbg(LOGLEVEL_ERROR, "Could not set master pubkey in Self Table");
    }
}

void migrate_legay_masterfile()
{
    if (!file_exists(legacy_masterpubkey_filename))
    {
        return;
    }

    dbg(LOGLEVEL_INFO, "migrating old legacy master file ...");

    FILE *f = fopen(legacy_masterpubkey_filename, "rb");
    if (! f)
    {
        return;
    }

    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (fsize < 1)
    {
        fclose(f);
        return;
    }

    char *legacy_master_pubkey = calloc(1, fsize + 2);
    long fsize_corr = fsize;
    if (fsize > (TOX_PUBLIC_KEY_SIZE * 2))
    {
        fsize_corr = TOX_PUBLIC_KEY_SIZE * 2;
    }
    size_t res = fread(legacy_master_pubkey, fsize_corr, 1, f);
    if (res) {}
    fclose(f);

    add_master(legacy_master_pubkey);
    unlink(legacy_masterpubkey_filename);
    dbg(LOGLEVEL_INFO, "migrating old legacy master file ... DONE");
}

void add_token(const char *token_str)
{
    // sqltoken
    Lov *l = orma_updateLov(o->db);
    int64_t affected_rows3 = l->valueSet(l, csb(token_str))->keyEq(l, csb(LOV_KEY_PUSHTOKEN))->execute(l);
    if (affected_rows3 < 1)
    {
        {
        Lov *p = orma_new_Lov(o->db);
        p->key = csb(LOV_KEY_PUSHTOKEN);
        p->value = csb(token_str);
        int64_t inserted_id = orma_insertIntoLov(p);
        if (inserted_id < 0)
        {
            dbg(LOGLEVEL_ERROR, "inserting pushtoken failed");
        }
        else
        {
            dbg(LOGLEVEL_INFO, "inserted pushtoken: %lld %s", (long long)inserted_id, token_str);
        }
        orma_free_Lov(p);
        }
    }
    else
    {
        dbg(LOGLEVEL_INFO, "updated pushtoken: %lld %s", (long long)affected_rows3, token_str);
    }
}

void read_token_from_db()
{
    // sqltoken
    Lov *p = orma_selectFromLov(o->db);
    LovList *pl = p->keyEq(p, csb(LOV_KEY_PUSHTOKEN))->toList(p);
    Lov **pd = pl->l;
    for(int i=0;i<pl->items;i++)
    {
        if ((*pd)->value->l > 2)
        {
            if (NOTIFICATION__device_token)
            {
                free(NOTIFICATION__device_token);
                NOTIFICATION__device_token = NULL;
            }
            // HINT: allocate 1 more byte for a NULL terminator in any case
            NOTIFICATION__device_token = calloc(1, (*pd)->value->l + 1);
            memcpy(NOTIFICATION__device_token, (*pd)->value->s, (*pd)->value->l);
        }
        // HINT: return after frist entry in any case
        orma_free_LovList(pl);
        return;
    }
    orma_free_LovList(pl);
}

bool is_master(const char *public_key_hex)
{
    // mastersql

    // --------- DEBUG ---------
    // --------- DEBUG ---------
    // --------- DEBUG ---------
    /*
    Self *s = orma_selectFromSelf(o->db);
    SelfList *sl = s->toList(s);
    Self **pd = sl->l;
    for(int i=0;i<sl->items;i++)
    {
        dbg(LOGLEVEL_DEBUG, "masterpubkey: _%s_ compare pk: _%s_", (*pd)->master_pubkey->s, public_key_hex);
    }
    orma_free_SelfList(sl);
     */
    // --------- DEBUG ---------
    // --------- DEBUG ---------
    // --------- DEBUG ---------

    Self *s2 = orma_selectFromSelf(o->db);
    int64_t count = s2->master_pubkeyEq(s2, csb(public_key_hex))->count(s2);
    if (count == 1)
    {
        dbg(LOGLEVEL_DEBUG, "is master %s: YES", public_key_hex);
        return true;
    }

    dbg(LOGLEVEL_DEBUG, "is master %s: no", public_key_hex);
    return false;
}

void getGroupIdHex_groupnumber(const Tox *tox, uint32_t group_number, char *hex)
{
    uint8_t _bin[tox_public_key_size()];
    CLEAR(_bin);
    tox_group_get_chat_id(tox, group_number, _bin, NULL);
    bin2upHex(_bin, TOX_GROUP_CHAT_ID_SIZE, hex, tox_group_key_hex_size);
}

void getPubKeyHex_friendnumber(const Tox *tox, uint32_t friend_number, char *pubKeyHex)
{
    uint8_t public_key_bin[tox_public_key_size()];
    CLEAR(public_key_bin);
    tox_friend_get_public_key(tox, friend_number, public_key_bin, NULL);
    bin2upHex(public_key_bin, tox_public_key_size(), pubKeyHex, tox_public_key_hex_size);
}

bool is_master_friendnumber(const Tox *tox, uint32_t friend_number)
{
    bool ret = false;
    char *pubKeyHex = calloc(1, tox_public_key_hex_size);
    getPubKeyHex_friendnumber(tox, friend_number, pubKeyHex);
    ret = is_master(pubKeyHex);
    free(pubKeyHex);
    return ret;
}

void friend_request_cb(Tox *tox, const uint8_t *public_key, const uint8_t *message, size_t UNUSED(length), void *UNUSED(user_data))
{
    char public_key_hex[tox_public_key_hex_size];
    CLEAR(public_key_hex);
    bin2upHex(public_key, tox_public_key_size(), public_key_hex, tox_public_key_hex_size);

    size_t friends = tox_self_get_friend_list_size(tox);

    if (friends == 0) {
        // add first friend as master for this proxy
        dbg(LOGLEVEL_INFO, "add first friend as master for this proxy");
        add_master(public_key_hex);
        tox_friend_add_norequest(tox, public_key, NULL);
        add_friend_to_db(public_key_hex, tox_public_key_hex_size_without_null_termin, true);
        updateToxSavedata(tox);
    } else {
        // once I have a master, I don't add friend's on request, only by command of my master!
        return;
    }

    dbg(LOGLEVEL_INFO, "Got currently %zu friends. New friend request from %s with message: %s",
                friends, public_key_hex, message);

    friends = tox_self_get_friend_list_size(tox);
    dbg(LOGLEVEL_INFO, "Added friend: %s. Number of total friends: %zu", public_key_hex, friends);
}

void friend_message_cb(Tox *UNUSED(tox), uint32_t friend_number, TOX_MESSAGE_TYPE UNUSED(type), const uint8_t *UNUSED(message),
                       size_t UNUSED(length), void *UNUSED(user_data))
{
    // char *default_msg = "YOU are using the old Message format! this is not supported!";
    // tox_friend_send_message(tox, friend_number, type, (uint8_t *) default_msg, strlen(default_msg), NULL);

    dbg(LOGLEVEL_WARN, "YOU are using the old Message format: fnum=%d", friend_number);
}

//
// cut message at 999 chars length !!
//
void send_text_message_to_friend(Tox *tox, uint32_t friend_number, const char *fmt, ...)
{
    dbg(LOGLEVEL_DEBUG, "sending message to friend %d", friend_number);
    const int max_msg_len = 1000;
    char msg2[max_msg_len];
    CLEAR(msg2);
    size_t length = 0;

    if (fmt == NULL) {
        dbg(LOGLEVEL_WARN, "send_text_message_to_friend:no message to send");
        return;
    }

    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg2, (max_msg_len - 1), fmt, ap);
    va_end(ap);
    length = (size_t) strlen(msg2);
#ifdef TOX_HAVE_TOXUTIL
    uint32_t ts_sec = (uint32_t) get_unix_time();
    tox_util_friend_send_message_v2(tox, friend_number, TOX_MESSAGE_TYPE_NORMAL, ts_sec, (const uint8_t *) msg2, length,
                                    NULL, NULL, NULL, NULL);
#else
    // old message format, not support by this proxy!
    tox_friend_send_message(tox, friend_number, TOX_MESSAGE_TYPE_NORMAL, (uint8_t *)msg2, length, NULL);
#endif
}

void friendlist_onConnectionChange(Tox *tox, uint32_t friend_number, TOX_CONNECTION connection_status, void *UNUSED(user_data))
{

    dbg(LOGLEVEL_DEBUG, "friendlist_onConnectionChange:*READY*:friendnum=%d %d", (int) friend_number, (int) connection_status);

    if (is_master_friendnumber(tox, friend_number)) {
        if (connection_status != TOX_CONNECTION_NONE) {
            dbg(LOGLEVEL_INFO, "master is online, send him all cached unsent messages");
            masterIsOnline = true;
        } else {
            dbg(LOGLEVEL_INFO, "master went offline, don't send him any more messages.");
            masterIsOnline = false;
        }
    }
}

void self_connection_status_cb(Tox *UNUSED(tox), TOX_CONNECTION connection_status, void *UNUSED(user_data))
{
    switch (connection_status) {
        case TOX_CONNECTION_NONE:
            dbg(LOGLEVEL_INFO, "Connection Status changed to: Offline");
            fprintf(stderr, "Connection Status changed to:Offline\n");
            my_connection_status = TOX_CONNECTION_NONE;
            on_offline();
            break;

        case TOX_CONNECTION_TCP:
            dbg(LOGLEVEL_INFO, "Connection Status changed to: Online via TCP");
            fprintf(stderr, "Connection Status changed to:Online via TCP\n");
            my_connection_status = TOX_CONNECTION_TCP;
            on_online();
            break;

        case TOX_CONNECTION_UDP:
            dbg(LOGLEVEL_INFO, "Connection Status changed to: Online via UDP");
            fprintf(stderr, "Connection Status changed to:Online via UDP\n");
            my_connection_status = TOX_CONNECTION_UDP;
            on_online();
            break;
    }
}

void conference_invite_cb(Tox *tox, uint32_t friend_number, TOX_CONFERENCE_TYPE UNUSED(type), const uint8_t *cookie,
                          size_t length, void *UNUSED(user_data))
{
    if (!is_master_friendnumber(tox, friend_number)) {
        uint8_t *f_name = get_friend_name(tox, friend_number);
        if (f_name)
        {
            dbg(LOGLEVEL_DEBUG, "received conference invite from somebody who's not master!:fnum=%d:fname=%s", friend_number, (char *)f_name);
        }
        else
        {
            dbg(LOGLEVEL_DEBUG, "received conference invite from somebody who's not master!:fnum=%d", friend_number);
        }
        return;
    }

    dbg(LOGLEVEL_DEBUG, "received conference invite from fnum:%d", friend_number);
    long conference_num = tox_conference_join(tox, friend_number, cookie, length, NULL);

    dbg(LOGLEVEL_DEBUG, "received conference join: res=%d", (int)conference_num);

    updateToxSavedata(tox);
}

void conference_message_cb(Tox *tox, uint32_t conference_number, uint32_t peer_number, TOX_MESSAGE_TYPE UNUSED(type),
                           const uint8_t *UNUSED(message), size_t UNUSED(length), void *UNUSED(user_data))
{
    dbg(LOGLEVEL_DEBUG, "enter conference_message_cb");
    dbg(LOGLEVEL_DEBUG, "received conference text message conf:%d peer:%d", conference_number, peer_number);

    uint8_t public_key_bin[TOX_PUBLIC_KEY_SIZE];
    CLEAR(public_key_bin);
    TOX_ERR_CONFERENCE_PEER_QUERY error;
    bool res = tox_conference_peer_get_public_key(tox, conference_number, peer_number, public_key_bin, &error);

    if (res == false) {
        dbg(LOGLEVEL_WARN, "received conference text message from peer without pubkey?");
        return;
    } else {
        char public_key_hex[tox_public_key_hex_size];
        CLEAR(public_key_hex);
        bin2upHex(public_key_bin, tox_public_key_size(), public_key_hex, tox_public_key_hex_size);

        if (is_master(public_key_hex)) {
            dbg(LOGLEVEL_DEBUG, "received conference text message from master");
        } else {
            uint8_t conference_id_buffer[TOX_CONFERENCE_ID_SIZE + 1];
            CLEAR(conference_id_buffer);
            bool res2 = tox_conference_get_id(tox, conference_number, conference_id_buffer);

            if (res2 == false) {
                dbg(LOGLEVEL_WARN, "conference id unknown?");
                return;
            } else {
                // ** DISABLE ** //
                // Conference messages no longer supported
            }
        }
    }
}

void conference_peer_list_changed_cb(Tox *tox, uint32_t UNUSED(conference_number), void *UNUSED(user_data))
{
    updateToxSavedata(tox);
}

void friend_sync_message_v2_cb(Tox *UNUSED(tox), uint32_t UNUSED(friend_number), const uint8_t *UNUSED(message), size_t UNUSED(length))
{
    dbg(LOGLEVEL_DEBUG, "enter friend_sync_message_v2_cb");
}

void friend_read_receipt_message_v2_cb(Tox *tox, uint32_t friend_number, uint32_t ts_sec, const uint8_t *msgid)
{
    char msgid2_str[tox_public_key_hex_size + 1];
    CLEAR(msgid2_str);
    bin2upHex(msgid, tox_public_key_size(), msgid2_str, tox_public_key_hex_size);

    dbg(LOGLEVEL_DEBUG, "enter friend_read_receipt_message_v2_cb:msgid=%s", msgid2_str);

    // HINT: delete group messages for that incoming receipt, if any
    Group_message *p = orma_deleteFromGroup_message(o->db);
    int64_t affected_rows2 = p->message_sync_hashidEq(p, csb(msgid2_str))->execute(p);
    dbg(LOGLEVEL_DEBUG, "deleteFromGroup_message: affected rows: %d\n", (int)affected_rows2);
    if (affected_rows2 > 0)
    {
        return;
    }

    // HINT: delete messages for that incoming receipt, if any
    Message *m = orma_deleteFromMessage(o->db);
    int64_t affected_rows3 = m->message_sync_hashidEq(m, csb(msgid2_str))->execute(m);
    dbg(LOGLEVEL_DEBUG, "deleteFromMessage: affected rows: %d\n", (int)affected_rows3);
    if (affected_rows3 > 0)
    {
        return;
    }

    // HINT: its an ACK, so save it into Message table
    uint32_t raw_message_len = tox_messagev2_size(0, TOX_FILE_KIND_MESSAGEV2_ANSWER, 0);
    uint8_t *raw_message_data = calloc(1, raw_message_len);

    bool res = tox_messagev2_wrap(0, TOX_FILE_KIND_MESSAGEV2_ANSWER,
                                  0, NULL, ts_sec, 0,
                                  raw_message_data, (uint8_t *)msgid);
    if (res){}


    // ----- SQL -----
    // ----- SQL -----
    // ----- SQL -----
    // ----- SQL -----
    // ----- SQL -----
    Message *gm = orma_new_Message(o->db);
    // -------

    uint8_t public_key_bin[tox_public_key_size()];
    CLEAR(public_key_bin);
    tox_friend_get_public_key(tox, friend_number, public_key_bin, NULL);
    char public_key_hex[tox_public_key_hex_size];
    CLEAR(public_key_hex);
    bin2upHex(public_key_bin, tox_public_key_size(), public_key_hex, tox_public_key_hex_size);

    uint32_t rawMsgSize2 = tox_messagev2_size(raw_message_len, TOX_FILE_KIND_MESSAGEV2_SYNC, 0);
    uint8_t *raw_message2 = calloc(1, rawMsgSize2);
    uint8_t *msgid3 = calloc(1, TOX_PUBLIC_KEY_SIZE);
    tox_messagev2_sync_wrap(raw_message_len, public_key_bin, TOX_FILE_KIND_MESSAGEV2_ANSWER,
                            raw_message_data, 987, 775, raw_message2, msgid3);
    dbg(LOGLEVEL_DEBUG, "friend_read_receipt_message_v2_cb: wrapped raw message = %p TOX_FILE_KIND_MESSAGEV2_SEND", raw_message2);
    char msgid3_str[tox_public_key_hex_size + 1];
    CLEAR(msgid3_str);
    bin2upHex(msgid3, tox_public_key_size(), msgid3_str, tox_public_key_hex_size);
    dbg(LOGLEVEL_DEBUG, "friend_read_receipt_message_v2_cb:msgid2=%s msgid_orig=%s", msgid3_str, msgid2_str);


    // -------
    dbg(LOGLEVEL_DEBUG, "friend_read_receipt_message_v2_cb:public_key_hex=%s", public_key_hex);
    gm->pubkey = csb(public_key_hex);
    // -------
    ASSIGN_B2UH_CSB(gm->datahex, raw_message_data, raw_message_len);
    // -------
    ASSIGN_B2UH_CSB(gm->wrappeddatahex, raw_message2, rawMsgSize2);
    // -------
    gm->timstamp_recv = (uint32_t)get_unix_time();
    // -------
    gm->mtype = TOX_FILE_KIND_MESSAGEV2_ANSWER;
    // -------
    gm->message_hashid = csb(msgid2_str);
    // -------
    gm->message_sync_hashid = csb(msgid3_str);
    // -------
    // -------
    int64_t inserted_id = orma_insertIntoMessage(gm);
    orma_free_Message(gm);
    dbg(LOGLEVEL_DEBUG, "Message ACK inserted id: %lld", (long long)inserted_id);

    free(msgid3);
    free(raw_message2);
    // ----- SQL -----
    // ----- SQL -----
    // ----- SQL -----
    // ----- SQL -----
    // ----- SQL -----






    free(raw_message_data);

}

void friend_message_v2_cb(Tox *tox, uint32_t friend_number, const uint8_t *raw_message, size_t raw_message_len)
{
    dbg(LOGLEVEL_DEBUG, "enter friend_message_v2_cb");

#ifdef TOX_HAVE_TOXUTIL
    // now get the real data from msgV2 buffer
    uint8_t *message_text = calloc(1, raw_message_len);

    if (message_text) {
        // uint32_t ts_sec = tox_messagev2_get_ts_sec(raw_message);
        // uint16_t ts_ms = tox_messagev2_get_ts_ms(raw_message);
        uint32_t text_length = 0;
        bool UNUSED(res) = tox_messagev2_get_message_text(raw_message, (uint32_t) raw_message_len, (bool) false, (uint32_t) 0,
                   message_text, &text_length);
        // dbg(LOGLEVEL_DEBUG, "friend_message_v2_cb:fn=%d res=%d msg=%s", (int) friend_number, (int) res, (char *) message_text);

        if (is_master_friendnumber(tox, friend_number)) {
            if ((strlen((char *) message_text) == (strlen("fp:") + tox_public_key_hex_size))
                    &&
                    (
                     strncmp((char *) message_text, "fp:", strlen("fp:")) == 0
                    )
               ) {
                char *pubKey = (char *)(message_text + 3);
                uint8_t public_key_bin[tox_public_key_size()];
                hex_string_to_bin(pubKey, tox_public_key_size() * 2, (char *) public_key_bin, tox_public_key_size());
                tox_friend_add_norequest(tox, public_key_bin, NULL);
                add_friend_to_db(pubKey, tox_public_key_hex_size_without_null_termin, false);
                updateToxSavedata(tox);
            } else if (
                          strlen((char *) message_text) == strlen("DELETE_EVERYTHING")
                       && strncmp((char *) message_text, "DELETE_EVERYTHING", (size_t)(strlen("DELETE_EVERYTHING"))) == 0
                      ) {
                killSwitch();
            } else {
                // send_text_message_to_friend(tox, friend_number, "Sorry, but this command has not been understood, please check the implementation or contact the developer.");
            }
        } else {
            // nicht vom master, also wohl ein freund vom master.




            if (masterIsOnline == false)
            {
                if (ping_push_service() == 1)
                {
                    ping_push_service();
                }
            }




            // ----- SQL -----
            // ----- SQL -----
            // ----- SQL -----
            // ----- SQL -----
            // ----- SQL -----
            Message *gm = orma_new_Message(o->db);
            // -------

            uint8_t public_key_bin[tox_public_key_size()];
            CLEAR(public_key_bin);
            tox_friend_get_public_key(tox, friend_number, public_key_bin, NULL);
            char public_key_hex[tox_public_key_hex_size];
            CLEAR(public_key_hex);
            bin2upHex(public_key_bin, tox_public_key_size(), public_key_hex, tox_public_key_hex_size);

            uint8_t *msg_id = calloc(1, tox_public_key_size());
            tox_messagev2_get_message_id(raw_message, msg_id);
            char msg_id_str[tox_public_key_hex_size + 1];
            CLEAR(msg_id_str);
            bin2upHex(msg_id, tox_public_key_size(), msg_id_str, tox_public_key_hex_size);
            dbg(LOGLEVEL_DEBUG, "friend_message_v2_cb:New message from %s msg_type=%d msg_id=%s", public_key_hex, TOX_FILE_KIND_MESSAGEV2_SEND, msg_id_str);
            free(msg_id);

            // ----------------------
            // ----------------------
            uint32_t rawMsgSize2 = tox_messagev2_size(raw_message_len, TOX_FILE_KIND_MESSAGEV2_SYNC, 0);
            uint8_t *raw_message2 = calloc(1, rawMsgSize2);
            uint8_t *msgid2 = calloc(1, TOX_PUBLIC_KEY_SIZE);
            tox_messagev2_sync_wrap(raw_message_len, public_key_bin, TOX_FILE_KIND_MESSAGEV2_SEND,
                                    raw_message, 987, 775, raw_message2, msgid2);
            dbg(LOGLEVEL_DEBUG, "friend_message_v2_cb: wrapped raw message = %p TOX_FILE_KIND_MESSAGEV2_SEND", raw_message2);
            char msgid2_str[tox_public_key_hex_size + 1];
            CLEAR(msgid2_str);
            bin2upHex(msgid2, tox_public_key_size(), msgid2_str, tox_public_key_hex_size);
            dbg(LOGLEVEL_DEBUG, "friend_message_v2_cb:msgid2=%s msgid_orig=%s", msgid2_str, msg_id_str);


            // -------
            dbg(LOGLEVEL_DEBUG, "friend_message_v2_cb:public_key_hex=%s", public_key_hex);
            gm->pubkey = csb(public_key_hex);
            // -------
            ASSIGN_B2UH_CSB(gm->datahex, raw_message, raw_message_len);
            // -------
            ASSIGN_B2UH_CSB(gm->wrappeddatahex, raw_message2, rawMsgSize2);
            // -------
            gm->timstamp_recv = (uint32_t)get_unix_time();
            // -------
            gm->mtype = TOX_FILE_KIND_MESSAGEV2_SEND;
            // -------
            gm->message_hashid = csb(msg_id_str);
            // -------
            gm->message_sync_hashid = csb(msgid2_str);
            // -------
            // -------
            int64_t inserted_id = orma_insertIntoMessage(gm);
            orma_free_Message(gm);
            dbg(LOGLEVEL_DEBUG, "Message inserted id: %lld", (long long)inserted_id);

            free(msgid2);
            free(raw_message2);
            // ----- SQL -----
            // ----- SQL -----
            // ----- SQL -----
            // ----- SQL -----
            // ----- SQL -----








            // send back an ACK, that toxproxy has received the message
            if (raw_message_len >= TOX_PUBLIC_KEY_SIZE)
            {
                uint8_t *msgid_acked = calloc(1, TOX_PUBLIC_KEY_SIZE);
                memcpy(msgid_acked, raw_message, TOX_PUBLIC_KEY_SIZE);

                char msgid_acked_str[tox_public_key_hex_size + 1];
                CLEAR(msgid_acked_str);
                bin2upHex(msgid_acked, tox_public_key_size(), msgid_acked_str, tox_public_key_hex_size);
                dbg(LOGLEVEL_DEBUG, "friend_message_v2_cb:msgid_acked=%s", msgid_acked_str);

                tox_util_friend_send_msg_receipt_v2(tox, friend_number, msgid_acked, 0);
            }
        }

        free(message_text);
    }

#endif
}

void friend_lossless_packet_cb(Tox *tox, uint32_t friend_number, const uint8_t *data, size_t length, void *UNUSED(user_data))
{
    dbg(LOGLEVEL_DEBUG, "enter friend_lossless_packet_cb");

    if (length == 0) {
        dbg(LOGLEVEL_DEBUG, "received empty lossless package!");
        return;
    }

    if (!is_master_friendnumber(tox, friend_number)) {
        if (data[0] != 170)
        {
            if (length > 0)
            {
                dbg(LOGLEVEL_DEBUG, "received lossless package from somebody who's not master! : id=%d", (int)data[0]);
            }
            else
            {
                dbg(LOGLEVEL_DEBUG, "received lossless package from somebody who's not master!");
            }
        }
        return;
    }

    if (data[0] == CONTROL_PROXY_MESSAGE_TYPE_PROXY_KILL_SWITCH) {
        killSwitch();
    } else if (data[0] == CONTROL_PROXY_MESSAGE_TYPE_NOTIFICATION_TOKEN) {
        if ((length > NOTI__device_token_min_len) && (length < NOTI__device_token_max_len))
        {
            // sqltoken
            dbg(LOGLEVEL_DEBUG, "received CONTROL_PROXY_MESSAGE_TYPE_NOTIFICATION_TOKEN message");
            char* tmp = calloc(1, (length + 1));
            memcpy(tmp, (data + 1), (length - 1));
            dbg(LOGLEVEL_DEBUG, "CONTROL_PROXY_MESSAGE_TYPE_NOTIFICATION_TOKEN: %s", tmp);
            fprintf(stderr, "received token:%s\n", tmp);
            // save notification token to file
            add_token(tmp);
            free(tmp);
            read_token_from_db();
        }
        return;
    } else if (data[0] == CONTROL_PROXY_MESSAGE_TYPE_FRIEND_PUBKEY_FOR_PROXY) {
        if (length != tox_public_key_size() + 1) {
            dbg(LOGLEVEL_WARN, "received ControlProxyMessageType_pubKey message with wrong size");
            return;
        }

        const uint8_t *public_key = data + 1;
        tox_friend_add_norequest(tox, public_key, NULL);
        updateToxSavedata(tox);
        char public_key_hex[tox_public_key_hex_size];
        CLEAR(public_key_hex);
        bin2upHex(public_key, tox_public_key_size(), public_key_hex, tox_public_key_hex_size);
        dbg(LOGLEVEL_DEBUG, "added friend of my master (norequest) with pubkey: %s", public_key_hex);
    } else if (data[0] == 170) {
        // toxutil.c CAP_PACKET_ID
    } else {
        dbg(LOGLEVEL_INFO, "received unexpected ControlProxyMessageType:id=%d", (int)data[0]);
    }
}

void send_sync_msgs_of_friend__messages(Tox *tox)
{
    Message *p = orma_selectFromMessage(o->db);
    MessageList *pl = p->orderBytimstamp_recvAsc(p)->toList(p);
    // dbg(LOGLEVEL_DEBUG, "pl->items=%lld", (long long)pl->items);
    Message **pd = pl->l;
    for(int i=0;i<pl->items;i++)
    {
        if (i == 0)
        {
            if (masterIsOnline == false)
            {
                if (ping_push_service() == 1)
                {
                    ping_push_service();
                }
            }
        }
        uint32_t rawMsgSize2 = ((*pd)->wrappeddatahex->l) / 2;
        uint8_t raw_message2[rawMsgSize2 + 1];
        memset(raw_message2, 0, (rawMsgSize2 + 1));
        H2B((*pd)->wrappeddatahex->s, raw_message2);

        TOX_ERR_FRIEND_SEND_MESSAGE error;
        bool res2 = tox_util_friend_send_sync_message_v2(tox, 0, raw_message2, rawMsgSize2, &error);
        dbg(LOGLEVEL_DEBUG, "send_sync_msgs_of_friend__messages: send_sync_msg res=%d; error=%d", (int)res2, error);

        pd++;
    }
    orma_free_MessageList(pl);
}

void send_sync_msgs_of_friend__groupmsgs(Tox *tox)
{
    Group_message *p = orma_selectFromGroup_message(o->db);
    Group_messageList *pl = p->orderBytimstamp_recvAsc(p)->toList(p);
    // dbg(LOGLEVEL_DEBUG, "pl->items=%lld", (long long)pl->items);
    Group_message **pd = pl->l;
    for(int i=0;i<pl->items;i++)
    {
        if (i == 0)
        {
            if (masterIsOnline == false)
            {
                if (ping_push_service() == 1)
                {
                    ping_push_service();
                }
            }
        }
        uint32_t rawMsgSize2 = ((*pd)->wrappeddatahex->l) / 2;
        uint8_t raw_message2[rawMsgSize2 + 1];
        memset(raw_message2, 0, (rawMsgSize2 + 1));
        H2B((*pd)->wrappeddatahex->s, raw_message2);

        TOX_ERR_FRIEND_SEND_MESSAGE error;
        bool res2 = tox_util_friend_send_sync_message_v2(tox, 0, raw_message2, rawMsgSize2, &error);
        dbg(LOGLEVEL_DEBUG, "send_sync_msgs_of_friend__groupmsgs: send_sync_msg res=%d; error=%d", (int)res2, error);

        pd++;
    }
    orma_free_Group_messageList(pl);
}

/*
 * HINT: this function sends friend messages and group messages to master
 */
void send_sync_msgs(Tox *tox)
{
    send_sync_msgs_of_friend__groupmsgs(tox);
    send_sync_msgs_of_friend__messages(tox);
}

struct curl_string {
    char *ptr;
    size_t len;
};

static void curl_init_string(struct curl_string *s)
{
    s->len = 0;
    s->ptr = calloc(1, s->len + 1);

    if (s->ptr == NULL)
    {
        dbg(LOGLEVEL_ERROR, "malloc() failed");
        exit(EXIT_FAILURE);
    }

    s->ptr[0] = '\0';
}

static size_t curl_writefunc(void *ptr, size_t size, size_t nmemb, struct curl_string *s)
{
    size_t new_len = s->len + size*nmemb;
    s->ptr = realloc(s->ptr, new_len+1);

    if (s->ptr == NULL)
    {
        dbg(LOGLEVEL_ERROR, "realloc() failed");
        exit(EXIT_FAILURE);
    }

    memcpy(s->ptr+s->len, ptr, size*nmemb);
    s->ptr[new_len] = '\0';
    s->len = new_len;

    return size*nmemb;
}

/*
 * return: 0 --> ok
 *         1 --> error
 */
int ping_push_service()
{
    dbg(LOGLEVEL_DEBUG, "ping_push_service");

    if (NOTIFICATION_METHOD == NOTIFICATION_METHOD_NONE)
    {
        dbg(LOGLEVEL_DEBUG, "ping_push_service:NOTIFICATION_METHOD NONE");
        return 1;
    }

    if (!NOTIFICATION__device_token)
    {
        dbg(LOGLEVEL_DEBUG, "ping_push_service: No NOTIFICATION__device_token");
        return 1;
    }

    if (NOTIFICATION_METHOD == NOTIFICATION_METHOD_GOTIFY_UP)
    {
        dbg(LOGLEVEL_DEBUG, "ping_push_service:NOTIFICATION_METHOD GOTIFY_UP");
        need_send_notification = 1;
        return 1;
    }
    else
    {
        return 1;
    }
}

/* TODO: CHECK */
static void *notification_thread_func(void *UNUSED(data))
{
    while (notification_thread_stop == 0)
    {
        if (need_send_notification == 1)
        {
            if (!NOTIFICATION__device_token)
            {
                // no notification token
            }
            else
            {
                if (NOTIFICATION_METHOD == NOTIFICATION_METHOD_GOTIFY_UP)
                {
                    dbg(LOGLEVEL_DEBUG, "ping_push_service:NOTIFICATION_METHOD GOTIFY_UP");
                    int result = 1;
                    CURL *curl = NULL;
                    CURLcode res = 0;

                    size_t max_buf_len = strlen(NOTIFICATION__device_token) + 1;

                    if (
                        (max_buf_len <= strlen(NOTIFICATION_GOTIFY_UP_PREFIX))
                        ||
                        (strncmp(NOTIFICATION_GOTIFY_UP_PREFIX, NOTIFICATION__device_token, strlen(NOTIFICATION_GOTIFY_UP_PREFIX)) != 0)
                       )
                    {
                        // HINT: token does not start with "https://"
                    }
                    else
                    {
                        char buf[max_buf_len + 1];
                        memset(buf, 0, max_buf_len + 1);
                        snprintf(buf, max_buf_len, "%s", NOTIFICATION__device_token);

                        curl = curl_easy_init();

                        if (curl)
                        {
                            struct curl_string s;
                            curl_init_string(&s);

                            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, "ping=1");
                            curl_easy_setopt(curl, CURLOPT_URL, buf);
                            curl_easy_setopt(curl, CURLOPT_USERAGENT, "Mozilla/5.0 (Windows NT 6.1; rv:60.0) Gecko/20100101 Firefox/60.0");

                            dbg(LOGLEVEL_DEBUG, "request=%s", buf);

                            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_writefunc);
                            curl_easy_setopt(curl, CURLOPT_WRITEDATA, &s);

                            res = curl_easy_perform(curl);

                            if (res != CURLE_OK)
                            {
                                dbg(LOGLEVEL_DEBUG, "curl_easy_perform() failed: %s", curl_easy_strerror(res));
                            }
                            else
                            {
                                long http_code = 0;
                                curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
                                if ((http_code < 300) && (http_code > 199))
                                {
                                    dbg(LOGLEVEL_DEBUG, "server_answer:OK:CURLINFO_RESPONSE_CODE=%ld, %s", http_code, s.ptr);
                                    result = 0;
                                }
                                else
                                {
                                    dbg(LOGLEVEL_DEBUG, "server_answer:ERROR:CURLINFO_RESPONSE_CODE=%ld, %s", http_code, s.ptr);
                                    result = 0; // do not retry, or the server may be spammed
                                }
                                free(s.ptr);
                                s.ptr = NULL;
                            }

                            curl_easy_cleanup(curl);
                        }

                        if (result == 0)
                        {
                            need_send_notification = 0;
                        }
                    }
                }
            }
        }
        usleep_usec(1000 * 500); // sleep 500 ms
    }

    dbg(LOGLEVEL_INFO, "Notification:Clean thread exit!");
    pthread_exit(0);
}

static void group_message_callback(Tox *tox, uint32_t groupnumber, uint32_t peer_number, TOX_MESSAGE_TYPE UNUSED(type),
                                   const uint8_t *message, size_t length, uint32_t message_id, void *UNUSED(userdata))
{
    dbg(LOGLEVEL_DEBUG, "received group text message group:%d peer:%d", groupnumber, peer_number);

    uint8_t public_key_bin[TOX_GROUP_PEER_PUBLIC_KEY_SIZE];
    CLEAR(public_key_bin);
    Tox_Err_Group_Peer_Query error;
    bool res = tox_group_peer_get_public_key(tox, groupnumber, peer_number, public_key_bin, &error);

    if (res == false) {
        dbg(LOGLEVEL_DEBUG, "received group text message from peer without pubkey?");
        return;
    } else {
        uint8_t group_id_buffer[TOX_GROUP_CHAT_ID_SIZE];
        CLEAR(group_id_buffer);
        bool res2 = tox_group_get_chat_id(tox, groupnumber, group_id_buffer, NULL);
        if (res2 == false) {
            dbg(LOGLEVEL_WARN, "group id unknown?");
            return;
        } else {

            if (masterIsOnline == false)
            {
                if (ping_push_service() == 1)
                {
                    ping_push_service();
                }
            }

            char public_key_hex[tox_public_key_hex_size];
            CLEAR(public_key_hex);
            bin2upHex(public_key_bin, tox_public_key_size(), public_key_hex, tox_public_key_hex_size);

#define HEX_MSG_NUM_LEN_COLON 9

            // --------- old way ---------
            // --------- old way ---------
            // --------- old way ---------
            // writeConferenceMessageHelper(tox, group_id_buffer, newmsg, (length + HEX_MSG_NUM_LEN_COLON), public_key_hex, 1);
            // --------- old way ---------
            // --------- old way ---------
            // --------- old way ---------

            // ----- SQL -----
            // ----- SQL -----
            // ----- SQL -----
            // ----- SQL -----
            // ----- SQL -----
            Group_message *gm = orma_new_Group_message(o->db);
            // -------
            size_t length_m_text = length + 64 + HEX_MSG_NUM_LEN_COLON;
            uint8_t *message_m = calloc(1, length_m_text);
            // put peer pubkey as uppercase hex in front of message
            memcpy(message_m, public_key_hex, 64);
            // add uint32_t message_id (as lowercase hex) + ":" in front of the text message bytes!!
            uint8_t *t1 = (uint8_t *)(&(message_id));
            uint8_t *t2 = t1 + 1;
            uint8_t *t3 = t1 + 2;
            uint8_t *t4 = t1 + 3;
            sprintf((char *)(message_m + 64), "%02x%02x%02x%02x:", *t4, *t3, *t2, *t1); // BEWARE: this adds a NULL byte at the end
            // put message bin after peer pubkey
            memcpy(message_m + 64 + HEX_MSG_NUM_LEN_COLON, message, length);

            uint32_t raw_message_len = tox_messagev2_size(length_m_text, TOX_FILE_KIND_MESSAGEV2_SEND, 0);
            dbg(LOGLEVEL_DEBUG, "writeConferenceMessageGr:raw_message_len=%d length_m_text=%d", raw_message_len, (int)length_m_text);
            uint8_t *raw_message_data = calloc(1, raw_message_len);
            uint32_t ts_sec = (uint32_t)get_unix_time();
            char msgid[TOX_PUBLIC_KEY_SIZE];
            CLEAR(msgid);
            bool res = tox_messagev2_wrap(length_m_text, TOX_FILE_KIND_MESSAGEV2_SEND,
                                        0, message_m, ts_sec, 0,
                                        raw_message_data, (uint8_t *)msgid);
            if (res) {}

            char msg_id_hex[tox_public_key_hex_size];
            CLEAR(msg_id_hex);
            bin2upHex((const uint8_t *)msgid, tox_public_key_size(), msg_id_hex, tox_public_key_hex_size);
            dbg(LOGLEVEL_DEBUG, "writeConferenceMessageGr:msg_id_hex=%s", msg_id_hex);



            // ----------------------
            // ----------------------
            uint32_t rawMsgSize2 = tox_messagev2_size(raw_message_len, TOX_FILE_KIND_MESSAGEV2_SYNC, 0);
            uint8_t *raw_message2 = calloc(1, rawMsgSize2);
            uint8_t *msgid2 = calloc(1, TOX_PUBLIC_KEY_SIZE);
            tox_messagev2_sync_wrap(raw_message_len, group_id_buffer, TOX_FILE_KIND_MESSAGEV2_SEND,
                                    raw_message_data, 987, 775, raw_message2, msgid2);
            dbg(LOGLEVEL_DEBUG, "send_sync_msg_single: wrapped raw message = %p TOX_FILE_KIND_MESSAGEV2_SEND", raw_message2);
            char msgid2_str[tox_public_key_hex_size + 1];
            CLEAR(msgid2_str);
            bin2upHex(msgid2, tox_public_key_size(), msgid2_str, tox_public_key_hex_size);
            dbg(LOGLEVEL_DEBUG, "send_sync_msg_single:msgid2=%s msgid_orig=%s", msgid2_str, msg_id_hex);



            // -------
            ASSIGN_B2UH_CSB(gm->groupid, group_id_buffer, TOX_GROUP_CHAT_ID_SIZE);
            // -------
            dbg(LOGLEVEL_DEBUG, "writeConferenceMessageGr:public_key_hex=%s", public_key_hex);
            gm->peerpubkey = csb(public_key_hex);
            // -------
            ASSIGN_B2UH_CSB(gm->datahex, message, length);
            // -------
            ASSIGN_B2UH_CSB(gm->wrappeddatahex, raw_message2, rawMsgSize2);
            // -------
            gm->message_id = message_id;
            // -------
            gm->timstamp_recv = ts_sec;
            // -------
            gm->message_hashid = csb(msg_id_hex);
            // -------
            gm->message_sync_hashid = csb(msgid2_str);
            // -------
            // -------
            int64_t inserted_id = orma_insertIntoGroup_message(gm);
            orma_free_Group_message(gm);
            dbg(LOGLEVEL_DEBUG, "group_message inserted id: %lld", (long long)inserted_id);

            free(message_m);
            free(raw_message_data);

            free(msgid2);
            free(raw_message2);
            // ----- SQL -----
            // ----- SQL -----
            // ----- SQL -----
            // ----- SQL -----
            // ----- SQL -----
        }
    }

}

static void group_invite_cb(Tox *tox, uint32_t friend_number, const uint8_t *invite_data, size_t length,
                                 const uint8_t *UNUSED(group_name), size_t UNUSED(group_name_length), void *UNUSED(user_data))
{
    size_t nick_len = tox_self_get_name_size(tox);
    char self_nick[TOX_MAX_NAME_LENGTH + 1];
    tox_self_get_name(tox, (uint8_t *) self_nick);
    self_nick[nick_len] = '\0';

    Tox_Err_Group_Invite_Accept error;
    uint32_t new_grp_num = tox_group_invite_accept(tox, friend_number, invite_data, length,
                                 (const uint8_t *)self_nick, nick_len, NULL, 0,
                                 &error);

    if (new_grp_num == UINT32_MAX)
    {
        dbg(LOGLEVEL_WARN, "tox_group_invite_accept failed");
    }
    else
    {
        uint8_t _txp_group_id_bin[tox_group_key_hex_size];
        CLEAR(_txp_group_id_bin);
        Tox_Err_Group_State_Queries err;
        tox_group_get_chat_id(tox, new_grp_num, _txp_group_id_bin, &err);
        if (err == TOX_ERR_GROUP_STATE_QUERIES_OK)
        {
            char _txp_group_id_hex[tox_group_key_hex_size];
            CLEAR(_txp_group_id_hex);
            bin2upHex(_txp_group_id_bin, TOX_GROUP_CHAT_ID_SIZE, _txp_group_id_hex, tox_group_key_hex_size);
            add_group_to_db(_txp_group_id_hex, tox_group_key_hex_size_without_null_termin);
        }

        dbg(LOGLEVEL_INFO, "tox_group_invite_accept:%d", error);
        updateToxSavedata(tox);
    }
}

static void group_peer_join_cb(Tox *tox, uint32_t group_number, uint32_t peer_id, void *UNUSED(user_data))
{
    dbg(LOGLEVEL_DEBUG, "Peer %d joined group %d", peer_id, group_number);
    updateToxSavedata(tox);
}

static void group_peer_exit_cb(Tox *tox, uint32_t group_number, uint32_t peer_id, Tox_Group_Exit_Type exit_type,
                                    const uint8_t *UNUSED(name), size_t UNUSED(name_length),
                                    const uint8_t *UNUSED(part_message), size_t UNUSED(length), void *UNUSED(user_data))
{
    switch (exit_type) {
        case TOX_GROUP_EXIT_TYPE_QUIT:
        dbg(LOGLEVEL_DEBUG, "Peer %d left group %d reason: %d TOX_GROUP_EXIT_TYPE_QUIT", peer_id, group_number, exit_type);
            break;
        case TOX_GROUP_EXIT_TYPE_TIMEOUT:
        dbg(LOGLEVEL_DEBUG, "Peer %d left group %d reason: %d TOX_GROUP_EXIT_TYPE_TIMEOUT", peer_id, group_number, exit_type);
            break;
        case TOX_GROUP_EXIT_TYPE_DISCONNECTED:
        dbg(LOGLEVEL_DEBUG, "Peer %d left group %d reason: %d TOX_GROUP_EXIT_TYPE_DISCONNECTED", peer_id, group_number, exit_type);
            break;
        case TOX_GROUP_EXIT_TYPE_SELF_DISCONNECTED:
        dbg(LOGLEVEL_DEBUG, "Peer %d left group %d reason: %d TOX_GROUP_EXIT_TYPE_SELF_DISCONNECTED", peer_id, group_number, exit_type);
            break;
        case TOX_GROUP_EXIT_TYPE_KICK:
        dbg(LOGLEVEL_DEBUG, "Peer %d left group %d reason: %d TOX_GROUP_EXIT_TYPE_KICK", peer_id, group_number, exit_type);
            break;
        case TOX_GROUP_EXIT_TYPE_SYNC_ERROR:
        dbg(LOGLEVEL_DEBUG, "Peer %d left group %d reason: %d TOX_GROUP_EXIT_TYPE_SYNC_ERROR", peer_id, group_number, exit_type);
            break;
    }
    updateToxSavedata(tox);
}

static void group_self_join_cb(Tox *tox, uint32_t group_number, void *UNUSED(user_data))
{
    dbg(LOGLEVEL_DEBUG, "You joined group %d", group_number);
    updateToxSavedata(tox);
}

static void group_join_fail_cb(Tox *tox, uint32_t group_number, Tox_Group_Join_Fail fail_type, void *UNUSED(user_data))
{
    dbg(LOGLEVEL_WARN, "Joining group %d failed. reason: %d", group_number, fail_type);
    updateToxSavedata(tox);
}

static void add_all_groups_to_db(const Tox *tox)
{
    size_t num_groups = tox_group_get_number_groups(tox);
    if (num_groups < 1)
    {
        return;
    }
    uint32_t *grouplist = calloc(num_groups, sizeof(uint32_t));
    if (grouplist == NULL)
    {
        return;
    }
    tox_group_get_grouplist(tox, grouplist);
    for(size_t k=0;k<num_groups;k++)
    {
        uint32_t gnum = grouplist[k];
        dbg(LOGLEVEL_DEBUG, "gnum=%d", gnum);
        char *groupIdHex = calloc(1, tox_group_key_hex_size);
        getGroupIdHex_groupnumber(tox, gnum, groupIdHex);
        dbg(LOGLEVEL_DEBUG, "gnum=%s", groupIdHex);
        add_group_to_db(groupIdHex, tox_group_key_hex_size_without_null_termin);
        free(groupIdHex);
    }
    free(grouplist);
}

static void add_all_friends_to_db(const Tox *tox)
{
    size_t num_friends = tox_self_get_friend_list_size(tox);
    if (num_friends < 1)
    {
        return;
    }
    uint32_t *friend_list = calloc(num_friends, sizeof(uint32_t));
    if (friend_list == NULL)
    {
        return;
    }
    tox_self_get_friend_list(tox, friend_list);
    for(size_t k=0;k<num_friends;k++)
    {
        uint32_t fnum = friend_list[k];
        // dbg(LOGLEVEL_DEBUG, "fnum=%d", fnum);
        char *pubKeyHex = calloc(1, tox_public_key_hex_size);
        getPubKeyHex_friendnumber(tox, fnum, pubKeyHex);
        add_friend_to_db(pubKeyHex, tox_public_key_hex_size_without_null_termin,
            is_master_friendnumber(tox, fnum));
        free(pubKeyHex);
    }
    free(friend_list);
}

int main(int argc, char *argv[])
{
    openLogFile();

    // ---- test ASAN ----
    // char *x = (char*)malloc(10 * sizeof(char*));
    // free(x);
    // x[0] = 1;
    // ---- test ASAN ----

    fprintf(stdout, "ToxProxy version: %s\n", global_version_string);
    dbg(LOGLEVEL_INFO, "ToxProxy version: %s", global_version_string);

#ifdef __MINGW32__
    mkdir(save_dir);
#else
    mkdir(save_dir, S_IRWXU);
#endif
    create_db();

    use_tor = 0;
    int opt;
    const char     *short_opt = "T";
    struct option   long_opt[] =
    {
        {"help",          no_argument,       NULL, 'h'},
        {"version",       no_argument,       NULL, 'v'},
        {NULL,            0,                 NULL,  0 }
    };


    while ((opt = getopt_long(argc, argv, short_opt, long_opt, NULL)) != -1)
    {
        switch (opt)
        {
            case -1:       /* no more arguments */
            case 0:        /* long options toggles */
                break;

            case 'T':
                use_tor = 1;
                break;

            case 'v':
                printf("ToxProxy version: %s\n", global_version_string);

                if (logfile)
                {
                    fclose(logfile);
                    logfile = NULL;
                }

                return (0);

            case 'h':
                printf("Usage: %s [OPTIONS]\n", argv[0]);
                printf("  -T,                                  use TOR as Relay\n");
                printf("  -v, --version                        show version\n");
                printf("  -h, --help                           print this help and exit\n");
                printf("\n");

                if (logfile)
                {
                    fclose(logfile);
                    logfile = NULL;
                }

                return (0);

            case ':':
            case '?':
                fprintf(stderr, "Try `%s --help' for more information.\n", argv[0]);

                if (logfile)
                {
                    fclose(logfile);
                    logfile = NULL;
                }

                return (-2);

            default:
                fprintf(stderr, "%s: invalid option -- %c\n", argv[0], opt);
                fprintf(stderr, "Try `%s --help' for more information.\n", argv[0]);

                if (logfile)
                {
                    fclose(logfile);
                    logfile = NULL;
                }

                return (-2);
        }
    }

    read_token_from_db();

    on_start();

    Tox *tox = openTox();

    tox_public_key_hex_size = tox_public_key_size() * 2 + 1;
    tox_public_key_hex_size_without_null_termin = tox_public_key_size() * 2;
    tox_address_hex_size = tox_address_size() * 2 + 1;
    tox_address_hex_size_without_null_termin = tox_address_size() * 2;

    uint8_t tox_id_bin[tox_address_size()];
    tox_self_get_address(tox, tox_id_bin);

    char toxid_hbuf[2*tox_address_size() + 1];
    B2UH(tox_id_bin, tox_address_size(), toxid_hbuf);


    // HINT: delete any entries with other toxid in the database -----------
    Self *p2 = orma_deleteFromSelf(o->db);
    int64_t deleted_rows = p2->toxidNotEq(p2, csc(toxid_hbuf, tox_address_hex_size_without_null_termin))->execute(p2);
    if (deleted_rows > 0)
    {
        dbg(LOGLEVEL_WARN, "deleted old toxid count: %lld", (long long)deleted_rows);
    }
    // HINT: delete any entries with other toxid in the database -----------

    {
    Self *p = orma_updateSelf(o->db);
    int64_t affected_rows3 = p->toxidSet(p, csc(toxid_hbuf, tox_address_hex_size_without_null_termin))->execute(p);
    if (affected_rows3 < 1)
    {
        {
        Self *p = orma_new_Self(o->db);
        p->toxid = csc(toxid_hbuf, tox_address_hex_size_without_null_termin);
        int64_t inserted_id = orma_insertIntoSelf(p);
        if (inserted_id < 0)
        {
            dbg(LOGLEVEL_ERROR, "inserting toxid failed");
        }
        else
        {
            dbg(LOGLEVEL_INFO, "inserted toxid: %lld", (long long)inserted_id);
        }
        orma_free_Self(p);
        }
    }
    else
    {
        dbg(LOGLEVEL_INFO, "updated toxid: %lld", (long long)affected_rows3);
    }
    }

#ifdef WRITE_MY_TOXID_TO_FILE
    FILE *fp = fopen(my_toxid_filename_txt, "wb");

    if (fp) {
        fprintf(fp, "%s", toxid_hbuf);
        fclose(fp);
    }

    FILE *fp2 = fopen(my_toxid_filename_txt2, "wb");

    if (fp2) {
        fprintf(fp2, "%s", toxid_hbuf);
        fclose(fp2);
    }
#endif

    migrate_legay_masterfile();

#if (NOTIFICATION_METHOD == NOTIFICATION_METHOD_GOTIFY_UP)
    curl_global_init(CURL_GLOBAL_ALL);
    need_send_notification = 0;
    notification_thread_stop = 0;

    if (pthread_create(&notification_thread, NULL, notification_thread_func, (void *)NULL) != 0)
    {
        dbg(LOGLEVEL_ERROR, "Notification Thread create failed");
    }
    else
    {
#ifndef __APPLE__
        pthread_setname_np(notification_thread, "t_notif");
#endif
        dbg(LOGLEVEL_INFO, "Notification Thread successfully created");
    }
#endif

    add_all_groups_to_db(tox);
    add_all_friends_to_db(tox);

    const char *name = "ToxProxy";
    tox_self_set_name(tox, (uint8_t *) name, strlen(name), NULL);

    const char *status_message = "Proxy for your messages";
    tox_self_set_status_message(tox, (uint8_t *) status_message, strlen(status_message), NULL);

    dbg(LOGLEVEL_INFO, "Tox bootstrapping ...");
    bootstrap(tox);

    dbg(LOGLEVEL_INFO, "ToxProxy startup completed");
    dbg(LOGLEVEL_INFO, "My Tox ID = %s", toxid_hbuf);

    size_t num_friends = tox_self_get_friend_list_size(tox);
    dbg(LOGLEVEL_INFO, "num_friends=%d", (int)num_friends);
    size_t num_conferences = tox_conference_get_chatlist_size(tox);
    dbg(LOGLEVEL_INFO, "num_conferences=%d", (int)num_conferences);
    size_t num_groups = tox_group_get_number_groups(tox);
    dbg(LOGLEVEL_INFO, "num_groups=%d", (int)num_groups);


    tox_callback_friend_request(tox, friend_request_cb);
    tox_callback_friend_message(tox, friend_message_cb);

#ifdef TOX_HAVE_TOXUTIL
    dbg(LOGLEVEL_INFO, "using toxutil");
    tox_utils_callback_self_connection_status(tox, self_connection_status_cb);
    tox_callback_self_connection_status(tox, tox_utils_self_connection_status_cb);
    tox_utils_callback_friend_connection_status(tox, friendlist_onConnectionChange);
    tox_callback_friend_connection_status(tox, tox_utils_friend_connection_status_cb);
    tox_utils_callback_friend_lossless_packet(tox, friend_lossless_packet_cb);
    tox_callback_friend_lossless_packet(tox, tox_utils_friend_lossless_packet_cb);
    // tox_utils_callback_file_recv_control(tox, on_file_control);
    tox_callback_file_recv_control(tox, tox_utils_file_recv_control_cb);
    // tox_utils_callback_file_chunk_request(tox, on_file_chunk_request);
    tox_callback_file_chunk_request(tox, tox_utils_file_chunk_request_cb);
    // tox_utils_callback_file_recv(tox, on_file_recv);
    tox_callback_file_recv(tox, tox_utils_file_recv_cb);
    // tox_utils_callback_file_recv_chunk(tox, on_file_recv_chunk);
    tox_callback_file_recv_chunk(tox, tox_utils_file_recv_chunk_cb);
    tox_utils_callback_friend_message_v2(tox, friend_message_v2_cb);
    tox_utils_callback_friend_read_receipt_message_v2(tox, friend_read_receipt_message_v2_cb);
    tox_utils_callback_friend_sync_message_v2(tox, friend_sync_message_v2_cb);
    tox_callback_conference_invite(tox, conference_invite_cb);
    tox_callback_conference_message(tox, conference_message_cb);
    tox_callback_conference_peer_list_changed(tox, conference_peer_list_changed_cb);
#else
    dbg(LOGLEVEL_ERROR, "NOT using toxutil");
    tox_callback_self_connection_status(tox, self_connection_status_cb);
    tox_callback_friend_connection_status(tox, friendlist_onConnectionChange);
#endif

    tox_callback_group_message(tox, group_message_callback);
    tox_callback_group_invite(tox, group_invite_cb);
    tox_callback_group_peer_join(tox, group_peer_join_cb);
    tox_callback_group_peer_exit(tox, group_peer_exit_cb);
    tox_callback_group_self_join(tox, group_self_join_cb);
    tox_callback_group_join_fail(tox, group_join_fail_cb);

    updateToxSavedata(tox);

    {
        Group_message *p = orma_selectFromGroup_message(o->db);
        Group_messageList *pl = p->toList(p);
        // dbg(LOGLEVEL_DEBUG, "pl->items=%lld", (long long)pl->items);
        if (pl->items > 0)
            {
            if (ping_push_service() == 1)
            {
                ping_push_service();
            }
        }
        orma_free_Group_messageList(pl);
    }



    long long unsigned int cur_time = time(NULL);
    long long loop_counter = 0;
    int max_tries = 2;

    int try = 0;

    uint8_t off = 1;

    while (1) {
        tox_iterate(tox, NULL);
        usleep_usec(tox_iteration_interval(tox) * 1000);


        if (tox_self_get_connection_status(tox) && off) {
            dbg(LOGLEVEL_INFO, "Tox online, took %llu seconds", time(NULL) - cur_time);

            fprintf(stdout, "#############################################################\n");
            fprintf(stdout, "#############################################################\n");
            fprintf(stdout, "\n");
            fprintf(stdout, "ToxID:%s\n", toxid_hbuf);
            fprintf(stdout, "\n");
            fprintf(stdout, "#############################################################\n");
            fprintf(stdout, "#############################################################\n");

            off = 0;
            break;
        }

        c_sleep(20);
        loop_counter++;

        if (loop_counter > (50 * 20)) {
            try++;

            loop_counter = 0;
            // if not yet online, bootstrap every 20 seconds
            dbg(LOGLEVEL_WARN, "Tox NOT online yet, (startup) bootstrapping again ...");
            bootstrap(tox);

            if (try >= max_tries) {
                    dbg(LOGLEVEL_WARN, "Tox NOT online for a long time, breaking bootstrap loop and starting iteration anyway.");

                    fprintf(stdout, "#############################################################\n");
                    fprintf(stdout, "#############################################################\n");
                    fprintf(stdout, "\n");
                    fprintf(stdout, "ToxID:%s\n", toxid_hbuf);
                    fprintf(stdout, "\n");
                    fprintf(stdout, "#############################################################\n");
                    fprintf(stdout, "#############################################################\n");

                    // break the loop and start anyway
                    // we will bootstrap again later if we are not online every few seconds
                    break;
                }
        }
    }

    tox_loop_running = 1;
    signal(SIGINT, sigint_handler);
#ifndef __APPLE__
    pthread_setname_np(pthread_self(), "t_main");
#endif

    int i = 0;

    while (tox_loop_running) {
        tox_iterate(tox, NULL);
        usleep_usec(tox_iteration_interval(tox) * 1000);
        // usleep_usec(50 * 1000);

// HINT: this is only an approximation
#define RETRY_SYNC_EVERY_X_SECONDS 20

        if ((masterIsOnline == true) && (i % (20 * RETRY_SYNC_EVERY_X_SECONDS) == 0)) {
            send_sync_msgs(tox);
        }

        // TODO: this is just to make sure stuff is saved
        //       make it better!
        if (i % 30000 == 0) {
            updateToxSavedata(tox);
        }

        i++;

        // check if we are offline for a while (more than 30 seconds)
        int am_i_online = 0;

        switch (my_connection_status) {
            case TOX_CONNECTION_NONE:
                break;

            case TOX_CONNECTION_TCP:
                am_i_online = 1;
                break;

            case TOX_CONNECTION_UDP:
                am_i_online = 1;
                break;

            default:
                break;
        }

        if (am_i_online == 0) {
            if ((my_last_online_ts + (BOOTSTRAP_AFTER_OFFLINE_SECS * 1000)) < (uint32_t)get_unix_time()) {
                // then bootstap again
                dbg(LOGLEVEL_INFO, "Tox NOT online, bootstrapping again ...");
                bootstrap(tox);
                // reset timestamp, that we do not bootstrap on every tox_iterate() loop
                my_last_online_ts = (uint32_t)get_unix_time();
            }
        }

    }

#ifdef TOX_HAVE_TOXUTIL
    tox_utils_kill(tox);
#else
    tox_kill(tox);
#endif

#if (NOTIFICATION_METHOD == NOTIFICATION_METHOD_GOTIFY_UP)
    notification_thread_stop = 1;
    pthread_join(notification_thread, NULL);

    curl_global_cleanup();
#endif

    shutdown_db();

    if (logfile) {
        fclose(logfile);
        logfile = NULL;
    }

    // HINT: for gprof you need an "exit()" call
    exit(0);
}

#ifdef __cplusplus
}  // extern "C"
#endif
