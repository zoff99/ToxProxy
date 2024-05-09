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
#define VERSION_PATCH 0
static const char global_version_string[] = "2.0.0";
// ----------- version -----------
// ----------- version -----------

// define this to write my own tox id to a text file
#define WRITE_MY_TOXID_TO_FILE

// define this to have the log statements also printed to stdout and not only into logfile
#define LOG2STDOUT

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
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <getopt.h>
#include <fcntl.h>
#include <assert.h>
#include <limits.h>
#include <stdbool.h>
#include <netdb.h>
#include <netinet/in.h>

#include <pthread.h>

#include <semaphore.h>
#include <signal.h>
#include <linux/sched.h>

// timestamps for printf output
#include <time.h>
#include <sys/time.h>

// mkdir -> https://linux.die.net/man/2/mkdir
#include <sys/stat.h>
#include <sys/types.h>

// gives bin2hex & hex2bin functions for Tox-ID / public-key conversions
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


static char *NOTIFICATION__device_token = NULL;
static const char *NOTIFICATION_GOTIFY_UP_PREFIX = "https://";

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

#define CURRENT_LOG_LEVEL 50 // 0 -> error, 1 -> warn, 2 -> info, 9 -> debug
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

const char *dbfilename = "toxproxy.db";

const char *savedata_filename = "./db/savedata.tox";
const char *savedata_tmp_filename = "./db/savedata.tox.tmp";

const char *empty_log_message = "empty log message received!";
const char *msgsDir = "./messages";
const char *masterFile = "./db/toxproxymasterpubkey.txt";
const char *tokenFile = "./db/token.txt";
const char *silent_marker = "is.silent";

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

    if (level <= CURRENT_LOG_LEVEL) {
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

// ---------- database functions ----------
// ---------- database functions ----------
// ---------- database functions ----------
// ---------- database functions ----------

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
}

static void add_group_to_db(const char *groupidhex, const uint32_t len)
{
    Group *g = orma_new_Group(o->db);
    g->groupid = csc(groupidhex, len);
    g->is_silent = false;
    int64_t inserted_id = orma_insertIntoGroup(g);
    dbg(LOGLEVEL_INFO, "added group to db, inserted id: %lld", (long long)inserted_id);
    orma_free_Group(g);
}

static void add_friend_to_db(const char *pubkeyhex, const uint32_t len, const bool is_master)
{
    Friend *f = orma_new_Friend(o->db);
    f->pubkey = csc(pubkeyhex, len);
    f->is_master = is_master;
    f->is_silent = false;
    int64_t inserted_id = orma_insertIntoFriend(f);
    dbg(LOGLEVEL_INFO, "added friend to db, inserted id: %lld", (long long)inserted_id);
    orma_free_Friend(f);
}

// ---------- database functions ----------
// ---------- database functions ----------
// ---------- database functions ----------

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

bool file_exists(const char *path)
{
    struct stat s;
    return stat(path, &s) == 0;
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

/* this works only for hex strings the length of (TOX_ADDRESS_SIZE*2) */
uint8_t *tox_address_hex_string_to_bin2(const char *hex_string)
{
    size_t len = TOX_ADDRESS_SIZE;
    uint8_t *val = calloc(1, len);

    for (size_t i = 0; i < len; ++i) {
        val[i] = (16 * char_to_int(hex_string[2 * i])) + (char_to_int(hex_string[2 * i + 1]));
    }

    return val;
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
    dbg(2, "got killSwitch command, deleting all data");
    unlink(savedata_filename);
    unlink(masterFile);
    unlink(tokenFile);
    dbg(1, "todo implement deleting messages");
    tox_loop_running = 0;
    exit(0);
}

void sigint_handler(int signo)
{
    if (signo == SIGINT) {
        printf("received SIGINT, pid=%d\n", getpid());
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
        dbg(0, "setting UDP mode");
    }
    else
    {
        options.udp_enabled = false; // TCP mode
        dbg(0, "setting TCP mode");
    }

    if (use_tor == 1)
    {
        dbg(0, "setting Tor Relay mode");
        options.udp_enabled = false; // TCP mode
        dbg(0, "setting TCP mode");
        const char *proxy_host = "127.0.0.1";
        dbg(0, "setting proxy_host %s", proxy_host);
        uint16_t proxy_port = PROXY_PORT_TOR_DEFAULT;
        dbg(0, "setting proxy_port %d", (int)proxy_port);
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
        dbg(99, "bootstap_nodes - sodium_hex2bin:res=%d", res);

        TOX_ERR_BOOTSTRAP error;
        res = tox_bootstrap(tox, nodes[i].ip, nodes[i].port, nodes[i].key_bin, &error);

        if (res != true) {
            if (error == TOX_ERR_BOOTSTRAP_OK) {
              dbg(9, "bootstrap:%s %d [FALSE]res=TOX_ERR_BOOTSTRAP_OK", nodes[i].ip, nodes[i].port);
            } else if (error == TOX_ERR_BOOTSTRAP_NULL) {
              dbg(9, "bootstrap:%s %d [FALSE]res=TOX_ERR_BOOTSTRAP_NULL", nodes[i].ip, nodes[i].port);
            } else if (error == TOX_ERR_BOOTSTRAP_BAD_HOST) {
              dbg(9, "bootstrap:%s %d [FALSE]res=TOX_ERR_BOOTSTRAP_BAD_HOST", nodes[i].ip, nodes[i].port);
            } else if (error == TOX_ERR_BOOTSTRAP_BAD_PORT) {
              dbg(9, "bootstrap:%s %d [FALSE]res=TOX_ERR_BOOTSTRAP_BAD_PORT", nodes[i].ip, nodes[i].port);
            }
        } else {
          dbg(9, "bootstrap:%s %d [TRUE] res=%d", nodes[i].ip, nodes[i].port, res);
        }

        if (add_as_tcp_relay == 1) {
            TOX_ERR_BOOTSTRAP error;
            res = tox_add_tcp_relay(tox, nodes[i].ip, nodes[i].port, nodes[i].key_bin, &error); // use also as TCP relay

            if (res != true) {
                if (error == TOX_ERR_BOOTSTRAP_OK) {
                  dbg(9, "add_tcp_relay:%s %d [FALSE] res=TOX_ERR_BOOTSTRAP_OK", nodes[i].ip, nodes[i].port);
                } else if (error == TOX_ERR_BOOTSTRAP_NULL) {
                  dbg(9, "add_tcp_relay:%s %d [FALSE] res=TOX_ERR_BOOTSTRAP_NULL", nodes[i].ip, nodes[i].port);
                } else if (error == TOX_ERR_BOOTSTRAP_BAD_HOST) {
                  dbg(9, "add_tcp_relay:%s %d [FALSE] res=TOX_ERR_BOOTSTRAP_BAD_HOST", nodes[i].ip, nodes[i].port);
                } else if (error == TOX_ERR_BOOTSTRAP_BAD_PORT) {
                  dbg(9, "add_tcp_relay:%s %d [FALSE] res=TOX_ERR_BOOTSTRAP_BAD_PORT", nodes[i].ip, nodes[i].port);
                }
            } else {
              dbg(9, "add_tcp_relay:%s %d [TRUE] res=%d", nodes[i].ip, nodes[i].port, res);
            }
        } else {
            dbg(2, "Not adding any TCP relays");
        }
    }
}

void bootstrap(Tox *tox)
{
    // use these nodes as tcp-relays
    DHT_node nodes_tcp_relays[] =
    {
        {"tox02.ky0uraku.xyz",33445, "D3D6D7C0C7009FC75406B0A49E475996C8C4F8BCE1E6FC5967DE427F8F600527", {0}},
        {"tox.plastiras.org",   443, "8E8B63299B3D520FB377FE5100E65E3322F7AE5B20A0ACED2981769FC5B43725", {0}},
        {"tox.initramfs.io",  33445, "3F0A45A268367C1BEA652F258C85F4A66DA76BCAA667A49E770BCC4917AB6A25", {0}},
        {"46.101.197.175",    33445, "CD133B521159541FB1D326DE9850F5E56A6C724B5B8E5EB5CD8D950408E95707", {0}},
        {"122.116.39.151",     3389, "5716530A10D362867C8E87EE1CD5362A233BAFBBA4CF47FA73B7CAD368BD5E6E", {0}},
        {"172.105.109.31",    33445, "D46E97CF995DC1820B92B7D899E152A217D36ABE22730FEA4B6BF1BFC06C617C", {0}},
        {"144.217.167.73",    33445, "7E5668E0EE09E19F320AD47902419331FFEE147BB3606769CFBE921A2A2FD34C", {0}},
        {"198.199.98.108",    33445, "BEF0CFB37AF874BD17B9A8F9FE64C75521DB95A37D33C5BDB00E9CF58659C04F", {0}},
        {"178.62.250.138",    33445, "788236D34978D1D5BD822F0A5BEBD2C53C64CC31CD3149350EE27D4D9A2F9B6B", {0}},
        {"136.243.141.187",   443,   "6EE1FADE9F55CC7938234CC07C864081FC606D8FE7B751EDA217F268F1078A39", {0}},
        {"185.14.30.213",     443,   "2555763C8C460495B14157D234DD56B86300A2395554BCAE4621AC345B8C1B1B", {0}},
        {"198.46.138.44",     33445, "F404ABAA1C99A9D37D61AB54898F56793E1DEF8BD46B1038B9D822E8460FAB67", {0}},
        {"51.15.37.145",      33445, "6FC41E2BD381D37E9748FC0E0328CE086AF9598BECC8FEB7DDF2E440475F300E", {0}},
        {"130.133.110.14",    33445, "461FA3776EF0FA655F1A05477DF1B3B614F7D6B124F7DB1DD4FE3C08B03B640F", {0}},
        {"205.185.116.116",   33445, "A179B09749AC826FF01F37A9613F6B57118AE014D4196A0E1105A98F93A54702", {0}},
        {"198.98.51.198",     33445, "1D5A5F2F5D6233058BF0259B09622FB40B482E4FA0931EB8FD3AB8E7BF7DAF6F", {0}},
        {"108.61.165.198",    33445, "8E7D0B859922EF569298B4D261A8CCB5FEA14FB91ED412A7603A585A25698832", {0}},
        {"194.249.212.109",   33445, "3CEE1F054081E7A011234883BC4FC39F661A55B73637A5AC293DDF1251D9432B", {0}},
        {"185.25.116.107",    33445, "DA4E4ED4B697F2E9B000EEFE3A34B554ACD3F45F5C96EAEA2516DD7FF9AF7B43", {0}},
        {"5.189.176.217",      5190, "2B2137E094F743AC8BD44652C55F41DFACC502F125E99E4FE24D40537489E32F", {0}},
        {"217.182.143.254",    2306, "7AED21F94D82B05774F697B209628CD5A9AD17E0C073D9329076A4C28ED28147", {0}},
        {"104.223.122.15",    33445, "0FB96EEBFB1650DDB52E70CF773DDFCABE25A95CC3BB50FC251082E4B63EF82A", {0}},
        {"tox.verdict.gg",    33445, "1C5293AEF2114717547B39DA8EA6F1E331E5E358B35F9B6B5F19317911C5F976", {0}},
        {"d4rk4.ru",           1813, "53737F6D47FA6BD2808F378E339AF45BF86F39B64E79D6D491C53A1D522E7039", {0}},
        {"104.233.104.126",   33445, "EDEE8F2E839A57820DE3DA4156D88350E53D4161447068A3457EE8F59F362414", {0}},
        {"51.254.84.212",     33445, "AEC204B9A4501412D5F0BB67D9C81B5DB3EE6ADA64122D32A3E9B093D544327D", {0}},
        {"88.99.133.52",      33445, "2D320F971EF2CA18004416C2AAE7BA52BF7949DB34EA8E2E21AF67BD367BE211", {0}},
        {"185.58.206.164",    33445, "24156472041E5F220D1FA11D9DF32F7AD697D59845701CDD7BE7D1785EB9DB39", {0}},
        {"92.54.84.70",       33445, "5625A62618CB4FCA70E147A71B29695F38CC65FF0CBD68AD46254585BE564802", {0}},
        {"195.93.190.6",      33445, "FB4CE0DDEFEED45F26917053E5D24BDDA0FA0A3D83A672A9DA2375928B37023D", {0}},
        {"tox.uplinklabs.net",33445, "1A56EA3EDF5DF4C0AEABBF3C2E4E603890F87E983CAC8A0D532A335F2C6E3E1F", {0}},
        {"toxnode.nek0.net",  33445, "20965721D32CE50C3E837DD75B33908B33037E6225110BFF209277AEAF3F9639", {0}},
        {"95.215.44.78",      33445, "672DBE27B4ADB9D5FB105A6BB648B2F8FDB89B3323486A7A21968316E012023C", {0}},
        {"163.172.136.118",   33445, "2C289F9F37C20D09DA83565588BF496FAB3764853FA38141817A72E3F18ACA0B", {0}},
        {"sorunome.de",       33445, "02807CF4F8BB8FB390CC3794BDF1E8449E9A8392C5D3F2200019DA9F1E812E46", {0}},
        {"37.97.185.116",     33445, "E59A0E71ADA20D35BD1B0957059D7EF7E7792B3D680AE25C6F4DBBA09114D165", {0}},
        {"193.124.186.205",   5228,  "9906D65F2A4751068A59D30505C5FC8AE1A95E0843AE9372EAFA3BAB6AC16C2C", {0}},
        {"80.87.193.193",     33445, "B38255EE4B054924F6D79A5E6E5889EC94B6ADF6FE9906F97A3D01E3D083223A", {0}},
        {"initramfs.io",      33445, "3F0A45A268367C1BEA652F258C85F4A66DA76BCAA667A49E770BCC4917AB6A25", {0}},
        {"hibiki.eve.moe",    33445, "D3EB45181B343C2C222A5BCF72B760638E15ED87904625AAD351C594EEFAE03E", {0}},
        {"tox.deadteam.org",  33445, "C7D284129E83877D63591F14B3F658D77FF9BA9BA7293AEB2BDFBFE1A803AF47", {0}},
        {"46.229.52.198",     33445, "813C8F4187833EF0655B10F7752141A352248462A567529A38B6BBF73E979307", {0}},
        {"node.tox.ngc.network", 33445, "A856243058D1DE633379508ADCAFCF944E40E1672FF402750EF712E30C42012A", {0}},
        {"144.217.86.39",     33445, "7E5668E0EE09E19F320AD47902419331FFEE147BB3606769CFBE921A2A2FD34C", {0}},
        {"185.14.30.213",       443, "2555763C8C460495B14157D234DD56B86300A2395554BCAE4621AC345B8C1B1B", {0}},
        {"77.37.160.178",     33440, "CE678DEAFA29182EFD1B0C5B9BC6999E5A20B50A1A6EC18B91C8EBB591712416", {0}},
        {"85.21.144.224",     33445, "8F738BBC8FA9394670BCAB146C67A507B9907C8E564E28C2B59BEBB2FF68711B", {0}},
        {"tox.natalenko.name", 33445, "1CB6EBFD9D85448FA70D3CAE1220B76BF6FCE911B46ACDCF88054C190589650B", {0}},
        {"37.187.122.30",     33445, "BEB71F97ED9C99C04B8489BB75579EB4DC6AB6F441B603D63533122F1858B51D", {0}},
        {"completelyunoriginal.moe", 33445, "FBC7DED0B0B662D81094D91CC312D6CDF12A7B16C7FFB93817143116B510C13E", {0}},
        {"136.243.141.187",     443, "6EE1FADE9F55CC7938234CC07C864081FC606D8FE7B751EDA217F268F1078A39", {0}},
        {"tox.abilinski.com", 33445, "0E9D7FEE2AA4B42A4C18FE81C038E32FFD8D907AAA7896F05AA76C8D31A20065", {0}},
        {"95.215.46.114",     33445, "5823FB947FF24CF83DDFAC3F3BAA18F96EA2018B16CC08429CB97FA502F40C23", {0}},
        {"51.15.54.207",      33445, "1E64DBA45EC810C0BF3A96327DC8A9D441AB262C14E57FCE11ECBCE355305239", {0}}
    };
    // use these nodes as bootstrap nodes
    DHT_node nodes_bootstrap_nodes[] =
    {
        {"178.62.250.138",    33445, "788236D34978D1D5BD822F0A5BEBD2C53C64CC31CD3149350EE27D4D9A2F9B6B", {0}},
        {"136.243.141.187",   443,   "6EE1FADE9F55CC7938234CC07C864081FC606D8FE7B751EDA217F268F1078A39", {0}},
        {"185.14.30.213",     443,   "2555763C8C460495B14157D234DD56B86300A2395554BCAE4621AC345B8C1B1B", {0}},
        {"198.46.138.44",     33445, "F404ABAA1C99A9D37D61AB54898F56793E1DEF8BD46B1038B9D822E8460FAB67", {0}},
        {"51.15.37.145",      33445, "6FC41E2BD381D37E9748FC0E0328CE086AF9598BECC8FEB7DDF2E440475F300E", {0}},
        {"130.133.110.14",    33445, "461FA3776EF0FA655F1A05477DF1B3B614F7D6B124F7DB1DD4FE3C08B03B640F", {0}},
        {"205.185.116.116",   33445, "A179B09749AC826FF01F37A9613F6B57118AE014D4196A0E1105A98F93A54702", {0}},
        {"198.98.51.198",     33445, "1D5A5F2F5D6233058BF0259B09622FB40B482E4FA0931EB8FD3AB8E7BF7DAF6F", {0}},
        {"108.61.165.198",    33445, "8E7D0B859922EF569298B4D261A8CCB5FEA14FB91ED412A7603A585A25698832", {0}},
        {"194.249.212.109",   33445, "3CEE1F054081E7A011234883BC4FC39F661A55B73637A5AC293DDF1251D9432B", {0}},
        {"185.25.116.107",    33445, "DA4E4ED4B697F2E9B000EEFE3A34B554ACD3F45F5C96EAEA2516DD7FF9AF7B43", {0}},
        {"5.189.176.217",      5190, "2B2137E094F743AC8BD44652C55F41DFACC502F125E99E4FE24D40537489E32F", {0}},
        {"217.182.143.254",    2306, "7AED21F94D82B05774F697B209628CD5A9AD17E0C073D9329076A4C28ED28147", {0}},
        {"104.223.122.15",    33445, "0FB96EEBFB1650DDB52E70CF773DDFCABE25A95CC3BB50FC251082E4B63EF82A", {0}},
        {"tox.verdict.gg",    33445, "1C5293AEF2114717547B39DA8EA6F1E331E5E358B35F9B6B5F19317911C5F976", {0}},
        {"d4rk4.ru",           1813, "53737F6D47FA6BD2808F378E339AF45BF86F39B64E79D6D491C53A1D522E7039", {0}},
        {"104.233.104.126",   33445, "EDEE8F2E839A57820DE3DA4156D88350E53D4161447068A3457EE8F59F362414", {0}},
        {"51.254.84.212",     33445, "AEC204B9A4501412D5F0BB67D9C81B5DB3EE6ADA64122D32A3E9B093D544327D", {0}},
        {"88.99.133.52",      33445, "2D320F971EF2CA18004416C2AAE7BA52BF7949DB34EA8E2E21AF67BD367BE211", {0}},
        {"185.58.206.164",    33445, "24156472041E5F220D1FA11D9DF32F7AD697D59845701CDD7BE7D1785EB9DB39", {0}},
        {"92.54.84.70",       33445, "5625A62618CB4FCA70E147A71B29695F38CC65FF0CBD68AD46254585BE564802", {0}},
        {"195.93.190.6",      33445, "FB4CE0DDEFEED45F26917053E5D24BDDA0FA0A3D83A672A9DA2375928B37023D", {0}},
        {"tox.uplinklabs.net",33445, "1A56EA3EDF5DF4C0AEABBF3C2E4E603890F87E983CAC8A0D532A335F2C6E3E1F", {0}},
        {"toxnode.nek0.net",  33445, "20965721D32CE50C3E837DD75B33908B33037E6225110BFF209277AEAF3F9639", {0}},
        {"95.215.44.78",      33445, "672DBE27B4ADB9D5FB105A6BB648B2F8FDB89B3323486A7A21968316E012023C", {0}},
        {"163.172.136.118",   33445, "2C289F9F37C20D09DA83565588BF496FAB3764853FA38141817A72E3F18ACA0B", {0}},
        {"sorunome.de",       33445, "02807CF4F8BB8FB390CC3794BDF1E8449E9A8392C5D3F2200019DA9F1E812E46", {0}},
        {"37.97.185.116",     33445, "E59A0E71ADA20D35BD1B0957059D7EF7E7792B3D680AE25C6F4DBBA09114D165", {0}},
        {"193.124.186.205",   5228,  "9906D65F2A4751068A59D30505C5FC8AE1A95E0843AE9372EAFA3BAB6AC16C2C", {0}},
        {"80.87.193.193",     33445, "B38255EE4B054924F6D79A5E6E5889EC94B6ADF6FE9906F97A3D01E3D083223A", {0}},
        {"initramfs.io",      33445, "3F0A45A268367C1BEA652F258C85F4A66DA76BCAA667A49E770BCC4917AB6A25", {0}},
        {"hibiki.eve.moe",    33445, "D3EB45181B343C2C222A5BCF72B760638E15ED87904625AAD351C594EEFAE03E", {0}},
        {"tox.deadteam.org",  33445, "C7D284129E83877D63591F14B3F658D77FF9BA9BA7293AEB2BDFBFE1A803AF47", {0}},
        {"46.229.52.198",     33445, "813C8F4187833EF0655B10F7752141A352248462A567529A38B6BBF73E979307", {0}},
        {"node.tox.ngc.network", 33445, "A856243058D1DE633379508ADCAFCF944E40E1672FF402750EF712E30C42012A", {0}},
        {"144.217.86.39",     33445, "7E5668E0EE09E19F320AD47902419331FFEE147BB3606769CFBE921A2A2FD34C", {0}},
        {"185.14.30.213",       443, "2555763C8C460495B14157D234DD56B86300A2395554BCAE4621AC345B8C1B1B", {0}},
        {"77.37.160.178",     33440, "CE678DEAFA29182EFD1B0C5B9BC6999E5A20B50A1A6EC18B91C8EBB591712416", {0}},
        {"85.21.144.224",     33445, "8F738BBC8FA9394670BCAB146C67A507B9907C8E564E28C2B59BEBB2FF68711B", {0}},
        {"tox.natalenko.name", 33445, "1CB6EBFD9D85448FA70D3CAE1220B76BF6FCE911B46ACDCF88054C190589650B", {0}},
        {"37.187.122.30",     33445, "BEB71F97ED9C99C04B8489BB75579EB4DC6AB6F441B603D63533122F1858B51D", {0}},
        {"completelyunoriginal.moe", 33445, "FBC7DED0B0B662D81094D91CC312D6CDF12A7B16C7FFB93817143116B510C13E", {0}},
        {"136.243.141.187",     443, "6EE1FADE9F55CC7938234CC07C864081FC606D8FE7B751EDA217F268F1078A39", {0}},
        {"tox.abilinski.com", 33445, "0E9D7FEE2AA4B42A4C18FE81C038E32FFD8D907AAA7896F05AA76C8D31A20065", {0}},
        {"95.215.46.114",     33445, "5823FB947FF24CF83DDFAC3F3BAA18F96EA2018B16CC08429CB97FA502F40C23", {0}},
        {"51.15.54.207",      33445, "1E64DBA45EC810C0BF3A96327DC8A9D441AB262C14E57FCE11ECBCE355305239", {0}}
    };
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wall"

    // bootstrap nodes
    bootstap_nodes(tox, nodes_bootstrap_nodes, (int)(sizeof(nodes_bootstrap_nodes) / sizeof(DHT_node)), 0);

    // tcp relay nodes
    bootstap_nodes(tox, nodes_tcp_relays, (int)(sizeof(nodes_tcp_relays) / sizeof(DHT_node)), 1);
#pragma GCC diagnostic pop
}

bool check_if_group_notifiation_silent(const char* groupid)
{
    char userDir[tox_public_key_hex_size + strlen(msgsDir) + 1 + 1];
    CLEAR(userDir);
    strcpy(userDir, msgsDir);
    strcat(userDir, "/");
    strcat(userDir, groupid);

    char *silentFilePath = calloc(1, sizeof(userDir) + 1 + strlen(silent_marker) + 5 + 1 + 1);
    strcpy(silentFilePath, userDir);
    strcat(silentFilePath, "/");
    strcat(silentFilePath, silent_marker);

    dbg(0, "checking for: %s", silentFilePath);
    if (file_exists(silentFilePath))
    {
        dbg(0, "group: %s is silent", groupid);
        free(silentFilePath);
        return true;
    }

    free(silentFilePath);
    return false;
}

void writeConferenceMessage(Tox *UNUSED(tox), const char *sender_group_key_hex, const uint8_t *message_orig, size_t length_orig,
                            uint32_t UNUSED(msg_type), char *peer_pubkey_hex, int is_group)
{
    size_t length = length_orig + 64;
    size_t len_copy = length_orig;

    // TODO: this is probably wrong, and should use max size of messageV2 ?
    if (length > TOX_MAX_MESSAGE_LENGTH) {
        length = TOX_MAX_MESSAGE_LENGTH;
        len_copy = TOX_MAX_MESSAGE_LENGTH - 64;
    }

    uint8_t *message = calloc(1, length);
    // put peer pubkey in front of message
    memcpy(message, peer_pubkey_hex, 64);
    // put message after peer pubkey
    memcpy(message + 64, message_orig, len_copy);

    uint32_t raw_message_len = tox_messagev2_size(length, TOX_FILE_KIND_MESSAGEV2_SEND, 0);

    dbg(0, "writeConferenceMessage:raw_message_len=%d length=%d", raw_message_len, (int)length);
    uint8_t *raw_message_data = calloc(1, raw_message_len);

    uint32_t ts_sec = (uint32_t) get_unix_time();

    char msgid[TOX_PUBLIC_KEY_SIZE];
    CLEAR(msgid);
    bool res = tox_messagev2_wrap(length, TOX_FILE_KIND_MESSAGEV2_SEND,
                                  0, message, ts_sec, 0,
                                  raw_message_data, (uint8_t *)msgid);
    if (res) {}

    char msg_id_hex[tox_public_key_hex_size];
    CLEAR(msg_id_hex);
    bin2upHex((const uint8_t *)msgid, tox_public_key_size(), msg_id_hex, tox_public_key_hex_size);
    dbg(0, "writeConferenceMessage:msg_id_hex=%s", msg_id_hex);

    char userDir[tox_public_key_hex_size + strlen(msgsDir) + 1 + 1];
    CLEAR(userDir);

    strcpy(userDir, msgsDir);
    strcat(userDir, "/");
    strcat(userDir, sender_group_key_hex);

    mkdir(msgsDir, S_IRWXU);
    mkdir(userDir, S_IRWXU);

    //TODO FIXME use message v2 message id / hash instead of timestamp of receiving / processing message!

    char timestamp[100]; // = "0000-00-00_0000-00,000000";
    CLEAR(timestamp);

    struct timeval tv;
    gettimeofday(&tv, NULL);
    struct tm tm = *localtime(&tv.tv_sec);
    snprintf(timestamp, sizeof(timestamp), "%04d-%02d-%02d_%02d%02d-%02d,%06ld",
             tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, tv.tv_usec);

    char *msgPath = calloc(1, sizeof(userDir) + 1 + sizeof(timestamp) + 5 + 1 + 1);
    strcpy(msgPath, userDir);
    strcat(msgPath, "/");
    strcat(msgPath, timestamp);
    strcat(msgPath, ".txtS");

    //if (count_file_in_dir(userDir) < MAX_FILES_IN_ONE_MESSAGE_DIR)
    // {
        FILE *f = fopen(msgPath, "wb");

        if (f) {
            fwrite(raw_message_data, raw_message_len, 1, f);
            fclose(f);
        }
    //}

    if (is_group != 1)
    {
        if (ping_push_service() == 1)
        {
            ping_push_service();
        }
    }
    else
    {
        // HINT: check if master wants to get push notifications for this NGC group
        bool is_silent = check_if_group_notifiation_silent(sender_group_key_hex);
        if (!is_silent)
        {
            if (ping_push_service() == 1)
            {
                ping_push_service();
            }
        }
    }

    free(raw_message_data);
    free(message);
    free(msgPath);
}

void writeMessage(char *sender_key_hex, const uint8_t *message, size_t length, uint32_t msg_type)
{

    uint8_t *msg_id = calloc(1, tox_public_key_size());
    tox_messagev2_get_message_id(message, msg_id);
    char msg_id_str[tox_public_key_hex_size + 1];
    CLEAR(msg_id_str);
    bin2upHex(msg_id, tox_public_key_size(), msg_id_str, tox_public_key_hex_size);
    dbg(2, "New message from %s msg_type=%d msg_id=%s", sender_key_hex, msg_type, msg_id_str);
    free(msg_id);

    char userDir[tox_public_key_hex_size + strlen(msgsDir) + 1 + 1];
    CLEAR(userDir);

    strcpy(userDir, msgsDir);
    strcat(userDir, "/");
    strcat(userDir, sender_key_hex);

    mkdir(msgsDir, S_IRWXU);
    mkdir(userDir, S_IRWXU);

    //TODO FIXME use message v2 message id / hash instead of timestamp of receiving / processing message!

    char timestamp[100]; // = "0000-00-00_0000-00,000000";
    CLEAR(timestamp);

    struct timeval tv;
    gettimeofday(&tv, NULL);
    struct tm tm = *localtime(&tv.tv_sec);
    snprintf(timestamp, sizeof(timestamp), "%04d-%02d-%02d_%02d%02d-%02d,%06ld",
             tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, tv.tv_usec);

    char *msgPath = calloc(1, sizeof(userDir) + 1 + sizeof(timestamp) + 5 + 1 + 1);
    strcpy(msgPath, userDir);
    strcat(msgPath, "/");
    strcat(msgPath, timestamp);

    if (msg_type == TOX_FILE_KIND_MESSAGEV2_ANSWER) {
        strcat(msgPath, ".txtA");
    } else if (msg_type == TOX_FILE_KIND_MESSAGEV2_SEND) {
        strcat(msgPath, ".txtS");
    }

    //if (count_file_in_dir(userDir) < max_files)
    //{
        FILE *f = fopen(msgPath, "wb");

        if (f) {
            fwrite(message, length, 1, f);
            fclose(f);
        }
    //}

    if (ping_push_service() == 1)
    {
        ping_push_service();
    }

    free(msgPath);
}

void writeMessageHelper(Tox *tox, uint32_t friend_number, const uint8_t *message, size_t length, uint32_t msg_type)
{
    uint8_t public_key_bin[tox_public_key_size()];
    CLEAR(public_key_bin);

    tox_friend_get_public_key(tox, friend_number, public_key_bin, NULL);

    char public_key_hex[tox_public_key_hex_size];
    CLEAR(public_key_hex);

    bin2upHex(public_key_bin, tox_public_key_size(), public_key_hex, tox_public_key_hex_size);
    writeMessage(public_key_hex, message, length, msg_type);
}

void writeConferenceMessageHelper(Tox *tox, const uint8_t *conference_id, const uint8_t *message, size_t length,
                                  char *peer_pubkey_hex, int is_group)
{
    if (is_group == 1)
    {
        char group_id_hex[tox_group_key_hex_size];
        CLEAR(group_id_hex);

        bin2upHex(conference_id, TOX_GROUP_CHAT_ID_SIZE, group_id_hex, (tox_group_key_hex_size));
        writeConferenceMessage(tox, group_id_hex, message, length, TOX_FILE_KIND_MESSAGEV2_SEND, peer_pubkey_hex, is_group);
    }
    else
    {
        char conference_id_hex[TOX_CONFERENCE_ID_SIZE * 2 + 1];
        CLEAR(conference_id_hex);

        bin2upHex(conference_id, TOX_CONFERENCE_ID_SIZE, conference_id_hex, (TOX_CONFERENCE_ID_SIZE * 2 + 1));
        writeConferenceMessage(tox, conference_id_hex, message, length, TOX_FILE_KIND_MESSAGEV2_SEND, peer_pubkey_hex, is_group);
    }
}

void add_master(const char *public_key_hex)
{

    if (file_exists(masterFile)) {
        dbg(2, "I already have a *MASTER*");
        return;
    }

    dbg(2, "added master");

    fprintf(stdout, "added master:%s\n", public_key_hex);

    FILE *f = fopen(masterFile, "wb");

    if (f) {
        fwrite(public_key_hex, tox_public_key_hex_size, 1, f);
        fclose(f);
    }
}

void add_token(const char *token_str)
{
    if (file_exists(tokenFile)) {
        dbg(2, "Tokenfile already exists, deleting it");
        unlink(tokenFile);
    }

    FILE *f = fopen(tokenFile, "wb");

    if (f) {
        fwrite(token_str, strlen(token_str), 1, f);
        fprintf(stdout, "saved token:%s\n", NOTIFICATION__device_token);
        dbg(2, "saved token:%s", NOTIFICATION__device_token);
        fclose(f);
    }
}

void read_token_from_file()
{
    if (!file_exists(tokenFile)) {
        return;
    }

    FILE *f = fopen(tokenFile, "rb");

    if (! f) {
        return;
    }

    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (fsize < 1) {
        fclose(f);
        return;
    }

    if (NOTIFICATION__device_token)
    {
        free(NOTIFICATION__device_token);
        NOTIFICATION__device_token = NULL;
    }

    NOTIFICATION__device_token = calloc(1, fsize + 2);
    size_t res = fread(NOTIFICATION__device_token, fsize, 1, f);
    if (res) {}

    fprintf(stdout, "loaded token:%s\n", NOTIFICATION__device_token);
    dbg(2, "loaded token:%s", NOTIFICATION__device_token);

    fclose(f);
}

bool is_master(const char *public_key_hex)
{
    //dbg(2, "enter:is_master");

    if (!file_exists(masterFile)) {
        dbg(2, "master file does not exist");
        return false;
    }

    FILE *f = fopen(masterFile, "rb");

    if (! f) {
        return false;
    }

    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (fsize < 1) {
        fclose(f);
        return false;
    }

    char *masterPubKeyHexSaved = calloc(1, fsize + 2);
    size_t res = fread(masterPubKeyHexSaved, fsize, 1, f);

    if (res) {}

    fclose(f);

    if (strncmp(masterPubKeyHexSaved, public_key_hex, tox_public_key_hex_size) == 0) {
        free(masterPubKeyHexSaved);
        return true;
    } else {
        free(masterPubKeyHexSaved);
        return false;
    }
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
        add_master(public_key_hex);
        tox_friend_add_norequest(tox, public_key, NULL);
        add_friend_to_db(public_key_hex, tox_public_key_hex_size_without_null_termin, true);
        updateToxSavedata(tox);
    } else {
        // once I have a master, I don't add friend's on request, only by command of my master!
        return;
    }

    dbg(2, "Got currently %zu friends. New friend request from %s with message: %s",
                friends, public_key_hex, message);

    friends = tox_self_get_friend_list_size(tox);
    dbg(2, "Added friend: %s. Number of total friends: %zu", public_key_hex, friends);
}

void friend_message_cb(Tox *UNUSED(tox), uint32_t friend_number, TOX_MESSAGE_TYPE UNUSED(type), const uint8_t *UNUSED(message),
                       size_t UNUSED(length), void *UNUSED(user_data))
{
    // char *default_msg = "YOU are using the old Message format! this is not supported!";
    // tox_friend_send_message(tox, friend_number, type, (uint8_t *) default_msg, strlen(default_msg), NULL);

    dbg(2, "YOU are using the old Message: fnum=%d", friend_number);
}

//
// cut message at 999 chars length !!
//
void send_text_message_to_friend(Tox *tox, uint32_t friend_number, const char *fmt, ...)
{
    dbg(9, "sending message to friend %d", friend_number);
    char msg2[1000];
    CLEAR(msg2);
    size_t length = 0;

    if (fmt == NULL) {
        dbg(9, "send_text_message_to_friend:no message to send");
        return;
    }

    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg2, 999, fmt, ap);
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

    dbg(2, "friendlist_onConnectionChange:*READY*:friendnum=%d %d", (int) friend_number, (int) connection_status);

    if (is_master_friendnumber(tox, friend_number)) {
        if (connection_status != TOX_CONNECTION_NONE) {
            dbg(2, "master is online, send him all cached unsent messages");
            masterIsOnline = true;
        } else {
            dbg(2, "master went offline, don't send him any more messages.");
            masterIsOnline = false;
        }
    }
}

void self_connection_status_cb(Tox *UNUSED(tox), TOX_CONNECTION connection_status, void *UNUSED(user_data))
{
    switch (connection_status) {
        case TOX_CONNECTION_NONE:
            dbg(2, "Connection Status changed to: Offline");
            fprintf(stdout, "Connection Status changed to:Offline\n");
            my_connection_status = TOX_CONNECTION_NONE;
            on_offline();
            break;

        case TOX_CONNECTION_TCP:
            dbg(2, "Connection Status changed to: Online via TCP");
            fprintf(stdout, "Connection Status changed to:Online via TCP\n");
            my_connection_status = TOX_CONNECTION_TCP;
            on_online();
            break;

        case TOX_CONNECTION_UDP:
            dbg(2, "Connection Status changed to: Online via UDP");
            fprintf(stdout, "Connection Status changed to:Online via UDP\n");
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
            dbg(0, "received conference invite from somebody who's not master!:fnum=%d:fname=%s", friend_number, (char *)f_name);
        }
        else
        {
            dbg(0, "received conference invite from somebody who's not master!:fnum=%d", friend_number);
        }
        return;
    }

    dbg(0, "received conference invite from fnum:%d", friend_number);
    long conference_num = tox_conference_join(tox, friend_number, cookie, length, NULL);

    dbg(0, "received conference join: res=%d", (int)conference_num);

    updateToxSavedata(tox);
}

void conference_message_cb(Tox *tox, uint32_t conference_number, uint32_t peer_number, TOX_MESSAGE_TYPE UNUSED(type),
                           const uint8_t *UNUSED(message), size_t UNUSED(length), void *UNUSED(user_data))
{
    dbg(9, "enter conference_message_cb");
    dbg(0, "received conference text message conf:%d peer:%d", conference_number, peer_number);

    uint8_t public_key_bin[TOX_PUBLIC_KEY_SIZE];
    CLEAR(public_key_bin);
    TOX_ERR_CONFERENCE_PEER_QUERY error;
    bool res = tox_conference_peer_get_public_key(tox, conference_number, peer_number, public_key_bin, &error);

    if (res == false) {
        dbg(0, "received conference text message from peer without pubkey?");
        return;
    } else {
        char public_key_hex[tox_public_key_hex_size];
        CLEAR(public_key_hex);
        bin2upHex(public_key_bin, tox_public_key_size(), public_key_hex, tox_public_key_hex_size);

        if (is_master(public_key_hex)) {
            dbg(0, "received conference text message from master");
        } else {
            uint8_t conference_id_buffer[TOX_CONFERENCE_ID_SIZE + 1];
            CLEAR(conference_id_buffer);
            bool res2 = tox_conference_get_id(tox, conference_number, conference_id_buffer);

            if (res2 == false) {
                dbg(0, "conference id unknown?");
                return;
            } else {
                // ** DISABLE ** // writeConferenceMessageHelper(tox, conference_id_buffer, message, length, public_key_hex, 0);
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
    dbg(9, "enter friend_sync_message_v2_cb");
}

/* TODO: CHECK */
bool is_answer_to_synced_message(Tox *tox, uint32_t friend_number, const uint8_t *message, size_t UNUSED(length))
{
    bool ret = false;

    uint8_t public_key_bin[tox_public_key_size()];
    CLEAR(public_key_bin);

    tox_friend_get_public_key(tox, friend_number, public_key_bin, NULL);

    char public_key_hex[tox_public_key_hex_size];
    CLEAR(public_key_hex);

    bin2upHex(public_key_bin, tox_public_key_size(), public_key_hex, tox_public_key_hex_size);

    uint8_t *msg_id = calloc(1, tox_public_key_size());
    if (msg_id)
    {
        tox_messagev2_get_message_id(message, msg_id);

        char msgid2_str[tox_public_key_hex_size + 1];
        CLEAR(msgid2_str);
        bin2upHex(msg_id, tox_public_key_size(), msgid2_str, tox_public_key_hex_size);

        dbg(2, "is_answer_to_synced_message: receipt from %s id __%s__", public_key_hex, msgid2_str);

        // find that message and delete the file for it ----------------

        mkdir(msgsDir, S_IRWXU);
        DIR *dfd_m = opendir(msgsDir);
        if (dfd_m == NULL)
        {
            free(msg_id);
            return false;
        }

        struct dirent *dp_m = NULL;

        while ((dp_m = readdir(dfd_m)) != NULL)
        {
            if (strlen(dp_m->d_name) > 2)
            {
                if (strncmp(dp_m->d_name, ".", 1) != 0 && strncmp(dp_m->d_name, "..", 2) != 0)
                {
                    // ****************************************
                    // dbg(2, "is_answer_to_synced_message: looping file:001:%s", dp_m->d_name);

                    char *friendDir = calloc(1, strlen(msgsDir) + 1 + strlen(dp_m->d_name) + 1);
                    sprintf(friendDir, "%s/%s", msgsDir, dp_m->d_name);

                    // dbg(2, "is_answer_to_synced_message: looping file:002:%s", friendDir);

                    mkdir(msgsDir, S_IRWXU);
                    DIR *dfd = opendir(friendDir);
                    if (dfd == NULL)
                    {
                        free(friendDir);
                        free(msg_id);
                        return false;
                    }

                    struct dirent *dp = NULL;

#define BASE_NAME_GLOB_LEN 31
#define END_PART_GLOB_LEN 68

                    while ((dp = readdir(dfd)) != NULL)
                    {
                        if (strlen(dp->d_name) > 2)
                        {
                            if (strncmp(dp->d_name, ".", 1) != 0 && strncmp(dp->d_name, "..", 2) != 0)
                            {
                                // dbg(2, "is_answer_to_synced_message: looping file:003:%s", dp->d_name);

                                int len = strlen(dp->d_name);
                                const char *last_char = &dp->d_name[len - 1];
                                if (strncmp(last_char, "_", 1) == 0)
                                {
                                    // dbg(2, "is_answer_to_synced_message: looping file:004:%s", last_char);

                                    const char *last_char2 = &dp->d_name[len - END_PART_GLOB_LEN];
                                    char *comp_str = calloc(1, (END_PART_GLOB_LEN + 2));
                                    sprintf(comp_str, "__%s__", msgid2_str);

                                    // dbg(2, "is_answer_to_synced_message: looping file:005:%s", last_char2);

                                    // dbg(2, "is_answer_to_synced_message: looping file:006:%s END_PART_GLOB_LEN=%d", comp_str, (int)END_PART_GLOB_LEN);

                                    if (strncmp(last_char2, comp_str, END_PART_GLOB_LEN) == 0)
                                    {
                                        // dbg(2, "is_answer_to_synced_message: found id %s in %s", comp_str, dp->d_name);
                                        // now delete all files for that id
                                        char *delete_file_glob = calloc(1, 1000);

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-truncation"
                                        int ret_snprintf = snprintf(delete_file_glob, BASE_NAME_GLOB_LEN, "%s", dp->d_name);
#pragma GCC diagnostic pop
                                        if (ret_snprintf){}
                                        char *run_cmd = calloc(1, 1000);
                                        sprintf(run_cmd, "rm %s/%s*", friendDir, delete_file_glob);
                                        // dbg(2, "is_answer_to_synced_message: running cmd: %s", run_cmd);
                                        int cmd_res = system(run_cmd);
                                        if (cmd_res){}
                                        // dbg(2, "is_answer_to_synced_message: cmd DONE");
                                        free(run_cmd);
                                        free(delete_file_glob);

                                        ret = true;
                                    }
                                    free(comp_str);
                                }
                            }
                        }
                    }

                    // find that message and delete the file for it ----------------
                    closedir(dfd);
                    free(friendDir);

                    // ****************************************
                }
            }
        }

        closedir(dfd_m);

        free(msg_id);
        return ret;
    }

    return false;
}

void friend_read_receipt_message_v2_cb(Tox *tox, uint32_t friend_number, uint32_t ts_sec, const uint8_t *msgid)
{
    char msgid2_str[tox_public_key_hex_size + 1];
    CLEAR(msgid2_str);
    bin2upHex(msgid, tox_public_key_size(), msgid2_str, tox_public_key_hex_size);

    dbg(9, "enter friend_read_receipt_message_v2_cb:msgid=%s", msgid2_str);

    // HINT: delete group messages for that incoming receipt, if any
    Group_message *p = orma_deleteFromGroup_message(o->db);
    int64_t affected_rows2 = p->message_sync_hashidEq(p, csb(msgid2_str))->execute(p);
    printf("deleteFromGroup_message: affected rows: %d\n", (int)affected_rows2);
    if (affected_rows2 > 0)
    {
        return;
    }

	// check if the received msg is confirm conference msg received
	// also: make long enough pauses in sending messages to master to allow for receipt msgs to come in and get processed.

#ifdef TOX_HAVE_TOXUTIL
    uint32_t raw_message_len = tox_messagev2_size(0, TOX_FILE_KIND_MESSAGEV2_ANSWER, 0);
    uint8_t *raw_message_data = calloc(1, raw_message_len);

    bool res = tox_messagev2_wrap(0, TOX_FILE_KIND_MESSAGEV2_ANSWER,
                                  0, NULL, ts_sec, 0,
                                  raw_message_data, (uint8_t *)msgid);
    if (res){}

    // check if this is an answer for a message we synced -> then just delete this message and not send it again
    // otherwise save the answer message

    if (is_answer_to_synced_message(tox, friend_number, raw_message_data, raw_message_len))
    {
        dbg(9, "is_answer_to_synced_message:YES");
    }
    else
    {
        dbg(9, "friend_read_receipt_message_v2_cb:call writeMessageHelper");
        // ** DISABLE ** // writeMessageHelper(tox, friend_number, raw_message_data, raw_message_len, TOX_FILE_KIND_MESSAGEV2_ANSWER);
    }

#endif

    free(raw_message_data);

}

void friend_message_v2_cb(Tox *tox, uint32_t friend_number, const uint8_t *raw_message, size_t raw_message_len)
{
    dbg(9, "enter friend_message_v2_cb");

#ifdef TOX_HAVE_TOXUTIL
    // now get the real data from msgV2 buffer
    uint8_t *message_text = calloc(1, raw_message_len);

    if (message_text) {
        // uint32_t ts_sec = tox_messagev2_get_ts_sec(raw_message);
        // uint16_t ts_ms = tox_messagev2_get_ts_ms(raw_message);
        uint32_t text_length = 0;
        bool UNUSED(res) = tox_messagev2_get_message_text(raw_message, (uint32_t) raw_message_len, (bool) false, (uint32_t) 0,
                   message_text, &text_length);
        // dbg(9, "friend_message_v2_cb:fn=%d res=%d msg=%s", (int) friend_number, (int) res, (char *) message_text);

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
            // dbg(9, "call writeMessageHelper()");
            // nicht vom master, also wohl ein freund vom master.









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
            dbg(2, "friend_message_v2_cb:New message from %s msg_type=%d msg_id=%s", public_key_hex, TOX_FILE_KIND_MESSAGEV2_SEND, msg_id_str);
            free(msg_id);

            // ----------------------
            // ----------------------
            uint32_t rawMsgSize2 = tox_messagev2_size(raw_message_len, TOX_FILE_KIND_MESSAGEV2_SYNC, 0);
            uint8_t *raw_message2 = calloc(1, rawMsgSize2);
            uint8_t *msgid2 = calloc(1, TOX_PUBLIC_KEY_SIZE);
            tox_messagev2_sync_wrap(raw_message_len, public_key_bin, TOX_FILE_KIND_MESSAGEV2_SEND,
                                    raw_message, 987, 775, raw_message2, msgid2);
            dbg(9, "friend_message_v2_cb: wrapped raw message = %p TOX_FILE_KIND_MESSAGEV2_SEND", raw_message2);
            char msgid2_str[tox_public_key_hex_size + 1];
            CLEAR(msgid2_str);
            bin2upHex(msgid2, tox_public_key_size(), msgid2_str, tox_public_key_hex_size);
            dbg(9, "friend_message_v2_cb:msgid2=%s msgid_orig=%s", msgid2_str, msg_id_str);


            // -------
            dbg(0, "friend_message_v2_cb:public_key_hex=%s", public_key_hex);
            gm->pubkey = csb(public_key_hex);
            // -------
            char group_msg_uhex[2*raw_message_len + 1];
            B2UH(raw_message, raw_message_len, group_msg_uhex);
            gm->datahex = csb(group_msg_uhex);
            // -------
            char group_wrappedmsg_uhex[2*rawMsgSize2 + 1];
            B2UH(raw_message2, rawMsgSize2, group_wrappedmsg_uhex);
            gm->wrappeddatahex = csb(group_wrappedmsg_uhex);
            // -------
            gm->timstamp_recv = (uint32_t)get_unix_time();
            // -------
            gm->message_hashid = csb(msg_id_str);
            // -------
            gm->message_sync_hashid = csb(msgid2_str);
            // -------
            // -------
            int64_t inserted_id = orma_insertIntoMessage(gm);
            orma_free_Message(gm);
            dbg(LOGLEVEL_INFO, "Message inserted id: %lld\n", (long long)inserted_id);

            free(msgid2);
            free(raw_message2);
            // ----- SQL -----
            // ----- SQL -----
            // ----- SQL -----
            // ----- SQL -----
            // ----- SQL -----













            // save the message to storage
            // ** DISABLE ** // writeMessageHelper(tox, friend_number, raw_message, raw_message_len, TOX_FILE_KIND_MESSAGEV2_SEND);

            // send back an ACK, that toxproxy has received the message
            if (raw_message_len >= TOX_PUBLIC_KEY_SIZE)
            {
                uint8_t *msgid_acked = calloc(1, TOX_PUBLIC_KEY_SIZE);
                memcpy(msgid_acked, raw_message, TOX_PUBLIC_KEY_SIZE);

                char msgid_acked_str[tox_public_key_hex_size + 1];
                CLEAR(msgid_acked_str);
                bin2upHex(msgid_acked, tox_public_key_size(), msgid_acked_str, tox_public_key_hex_size);
                dbg(9, "friend_message_v2_cb:msgid_acked=%s", msgid_acked_str);

                tox_util_friend_send_msg_receipt_v2(tox, friend_number, msgid_acked, 0);
            }
        }

        free(message_text);
    }

#endif
}

void friend_lossless_packet_cb(Tox *tox, uint32_t friend_number, const uint8_t *data, size_t length, void *UNUSED(user_data))
{
    dbg(9, "enter friend_lossless_packet_cb");

    if (length == 0) {
        dbg(0, "received empty lossless package!");
        return;
    }

    if (!is_master_friendnumber(tox, friend_number)) {
        if (data[0] != 170)
        {
            if (length > 0)
            {
                dbg(0, "received lossless package from somebody who's not master! : id=%d", (int)data[0]);
            }
            else
            {
                dbg(0, "received lossless package from somebody who's not master!");
            }
        }
        return;
    }

    if (data[0] == CONTROL_PROXY_MESSAGE_TYPE_PROXY_KILL_SWITCH) {
        killSwitch();
    } else if (data[0] == CONTROL_PROXY_MESSAGE_TYPE_NOTIFICATION_TOKEN) {
        if ((length > NOTI__device_token_min_len) && (length < NOTI__device_token_max_len))
        {
            dbg(0, "received CONTROL_PROXY_MESSAGE_TYPE_NOTIFICATION_TOKEN message");
            NOTIFICATION__device_token = calloc(1, (length + 1));
            memcpy(NOTIFICATION__device_token, (data + 1), (length - 1));
            dbg(0, "CONTROL_PROXY_MESSAGE_TYPE_NOTIFICATION_TOKEN: %s", NOTIFICATION__device_token);
            fprintf(stdout, "received token:%s\n", NOTIFICATION__device_token);
            // save notification token to file
            add_token(NOTIFICATION__device_token);
        }
        return;
    } else if (data[0] == CONTROL_PROXY_MESSAGE_TYPE_FRIEND_PUBKEY_FOR_PROXY) {
        if (length != tox_public_key_size() + 1) {
            dbg(0, "received ControlProxyMessageType_pubKey message with wrong size");
            return;
        }

        const uint8_t *public_key = data + 1;
        tox_friend_add_norequest(tox, public_key, NULL);
        updateToxSavedata(tox);
        char public_key_hex[tox_public_key_hex_size];
        CLEAR(public_key_hex);
        bin2upHex(public_key, tox_public_key_size(), public_key_hex, tox_public_key_hex_size);
        dbg(0, "added friend of my master (norequest) with pubkey: %s", public_key_hex);
    } else if (data[0] == 170) {
        // toxutil.c CAP_PACKET_ID
    } else {
        dbg(0, "received unexpected ControlProxyMessageType:id=%d", (int)data[0]);
    }
}

void send_sync_msg_single(Tox *tox, char *pubKeyHex, char *msgFileName)
{
    char *msgPath = calloc(1, strlen(msgsDir) + 1 + strlen(pubKeyHex) + 1 + strlen(msgFileName) + 1);

    // last +1 is for terminating \0 I guess (without it, memory checker explodes..)
    sprintf(msgPath, "%s/%s/%s", msgsDir, pubKeyHex, msgFileName);

    char userDir[tox_public_key_hex_size + strlen(msgsDir) + 1 + 1];
    CLEAR(userDir);
    sprintf(userDir, "%s/%s", msgsDir, pubKeyHex);

    FILE *f = fopen(msgPath, "rb");
    if (f) {
        fseek(f, 0, SEEK_END);
        long fsize = ftell(f);
        fseek(f, 0, SEEK_SET);

        if (fsize < 1) {
            fclose(f);
            free(msgPath);
            return;
        }

        uint8_t *rawMsgData = calloc(1, fsize);
        size_t ret = fread(rawMsgData, fsize, 1, f);

        // TODO: handle ret return vlaue here!
        if (ret) {
            // ------
        }

        fclose(f);


        uint32_t rawMsgSize2 = tox_messagev2_size(fsize, TOX_FILE_KIND_MESSAGEV2_SYNC, 0);
        uint8_t *raw_message2 = calloc(1, rawMsgSize2);
        uint8_t *msgid2 = calloc(1, TOX_PUBLIC_KEY_SIZE);
        uint8_t *pubKeyBin = tox_address_hex_string_to_bin2(pubKeyHex);

        if (msgFileName[strlen(msgFileName) - 1] == 'A') {
            // TOX_FILE_KIND_MESSAGEV2_ANSWER
            tox_messagev2_sync_wrap(fsize, pubKeyBin, TOX_FILE_KIND_MESSAGEV2_ANSWER,
                                    rawMsgData, 665, 987, raw_message2, msgid2);
            dbg(9, "send_sync_msg_single: wrapped raw message = %p TOX_FILE_KIND_MESSAGEV2_ANSWER", raw_message2);
        } else { // TOX_FILE_KIND_MESSAGEV2_SEND
            tox_messagev2_sync_wrap(fsize, pubKeyBin, TOX_FILE_KIND_MESSAGEV2_SEND,
                                    rawMsgData, 987, 775, raw_message2, msgid2);
            dbg(9, "send_sync_msg_single: wrapped raw message = %p TOX_FILE_KIND_MESSAGEV2_SEND", raw_message2);
        }

        // save new msgid ----------
        char msgid2_str[tox_public_key_hex_size + 1];
        CLEAR(msgid2_str);
        bin2upHex(msgid2, tox_public_key_size(), msgid2_str, tox_public_key_hex_size);

        char msgid_orig_str[tox_public_key_hex_size + 1];
        CLEAR(msgid_orig_str);
        bin2upHex(rawMsgData, tox_public_key_size(), msgid_orig_str, tox_public_key_hex_size);

        dbg(9, "send_sync_msg_single:msgid2=%s msgid_orig=%s", msgid2_str, msgid_orig_str);

        char *msgPath_msg_id = calloc(1, 1000);
        if (msgPath_msg_id)
        {
            sprintf(msgPath_msg_id, "%s__%s__", msgPath, msgid2_str);
            dbg(9, "send_sync_msg_single: writing new msg_id to file: %s", msgPath_msg_id);

            //if (count_file_in_dir(userDir) < max_files)
            //{
                FILE *f_msg_id = fopen(msgPath_msg_id, "wb");
                fwrite(msgid_orig_str, tox_public_key_size(), 1, f_msg_id); // write the original msg_id into the file
                fclose(f_msg_id);
            //}

            free(msgPath_msg_id);
        }
        // save new msgid ----------

        TOX_ERR_FRIEND_SEND_MESSAGE error;
        bool res2 = tox_util_friend_send_sync_message_v2(tox, 0, raw_message2, rawMsgSize2, &error);
        dbg(9, "send_sync_msg_single: send_sync_msg res=%d; error=%d", (int)res2, error);

        free(rawMsgData);
        free(raw_message2);
        free(pubKeyBin);
        free(msgid2);

        // do not delete messages here!! // unlink(msgPath);
    }

    free(msgPath);
}

void send_sync_msgs_of_friend(Tox *tox, char *pubKeyHex)
{
    // dbg(9, "enter send_sync_msgs_of_friend");
    // dbg(3, "sending messages of friend: %s to master", pubKeyHex);

    char *friendDir = calloc(1, strlen(msgsDir) + 1 + strlen(pubKeyHex) +
                             1); // last +1 is for terminating \0 I guess (without it, memory checker explodes..)
    sprintf(friendDir, "%s/%s", msgsDir, pubKeyHex);

    mkdir(msgsDir, S_IRWXU);

    DIR *dfd = opendir(friendDir);

    if (dfd == NULL) {
        // dbg(1, "Can't open msgsDir for sending messages to master (maybe no single message has been received yet?)");
        free(friendDir);
        return;
    }

    struct dirent *dp = NULL;

    // char filename_qfd[260];
    // char new_name_qfd[100];

    while ((dp = readdir(dfd)) != NULL) {
        if (strlen(dp->d_name) > 2)
        {
            if (strncmp(dp->d_name, ".", 1) != 0 && strncmp(dp->d_name, "..", 2) != 0)
            {
                int len = strlen(dp->d_name);
                const char *last_char = &dp->d_name[len - 1];
                if (strncmp(last_char, "_", 1) != 0)
                {
                    if (strncmp(dp->d_name, "is.silent", strlen("is.silent")) != 0)
                    {
                        dbg(2, "found message by %s with filename %s", pubKeyHex, dp->d_name);
                        send_sync_msg_single(tox, pubKeyHex, dp->d_name);
                    }
                }
            }
        }
    }

    closedir(dfd);
    free(friendDir);
}

void send_sync_msgs_of_friend__groupmsgs(Tox *tox)
{
    Group_message *p = orma_selectFromGroup_message(o->db);
    Group_messageList *pl = p->toList(p);
    dbg(LOGLEVEL_DEBUG, "pl->items=%lld\n", (long long)pl->items);
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
        printf("GM: id=%ld\n", (*pd)->id);
        printf("GM: message_id=\"%d\"\n", (uint32_t)(*pd)->message_id);
        printf("GM: message_text_length_hex=\"%d\"\n", (*pd)->datahex->l);
        printf("GM: peerpubkey len=\"%d\"\n", (*pd)->peerpubkey->l);
        printf("GM: peerpubkey str=\"%s\"\n", (*pd)->peerpubkey->s);

        uint32_t rawMsgSize2 = ((*pd)->wrappeddatahex->l) / 2;
        uint8_t raw_message2[rawMsgSize2 + 1];
        memset(raw_message2, 0, (rawMsgSize2 + 1));
        H2B((*pd)->wrappeddatahex->s, raw_message2);
        // ----------------------
        // ----------------------
        /*** ***/
        /*** ***/
        /*** ***/
        TOX_ERR_FRIEND_SEND_MESSAGE error;
        bool res2 = tox_util_friend_send_sync_message_v2(tox, 0, raw_message2, rawMsgSize2, &error);
        dbg(9, "send_sync_msg_single: send_sync_msg res=%d; error=%d", (int)res2, error);
        /*** ***/
        /*** ***/
        /*** ***/
        pd++;
    }
    orma_free_Group_messageList(pl);
}

/*
 * HINT: this function send friend messages and conference and group messages to master
 */
void send_sync_msgs(Tox *tox)
{
    send_sync_msgs_of_friend__groupmsgs(tox);

    mkdir(msgsDir, S_IRWXU);

    // loop over all directories = public-keys of friends we have received messages from
    DIR *dfd = opendir(msgsDir);

    if (dfd == NULL) {
        // dbg(1, "Can't open msgsDir for sending messages to master (maybe no single message has been received yet?)");
        return;
    }

    struct dirent *dp = NULL;

    while ((dp = readdir(dfd)) != NULL) {
        if (strncmp(dp->d_name, ".", 1) != 0 && strncmp(dp->d_name, "..", 2) != 0) {
            // ** DISBALE ** // send_sync_msgs_of_friend(tox, dp->d_name);
        }
    }

    closedir(dfd);
}

struct string {
    char *ptr;
    size_t len;
};

static void init_string(struct string *s)
{
    s->len = 0;
    s->ptr = calloc(1, s->len + 1);

    if (s->ptr == NULL)
    {
        dbg(9, "malloc() failed");
        exit(EXIT_FAILURE);
    }

    s->ptr[0] = '\0';
}

static size_t writefunc(void *ptr, size_t size, size_t nmemb, struct string *s)
{
    size_t new_len = s->len + size*nmemb;
    s->ptr = realloc(s->ptr, new_len+1);

    if (s->ptr == NULL)
    {
        dbg(9, "realloc() failed");
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
    dbg(9, "ping_push_service");

    if (NOTIFICATION_METHOD == NOTIFICATION_METHOD_NONE)
    {
        dbg(9, "ping_push_service:NOTIFICATION_METHOD NONE");
        return 1;
    }

    if (!NOTIFICATION__device_token)
    {
        dbg(9, "ping_push_service: No NOTIFICATION__device_token");
        return 1;
    }

    if (NOTIFICATION_METHOD == NOTIFICATION_METHOD_GOTIFY_UP)
    {
        dbg(9, "ping_push_service:NOTIFICATION_METHOD GOTIFY_UP");
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
                    dbg(9, "ping_push_service:NOTIFICATION_METHOD GOTIFY_UP");
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
                            struct string s;
                            init_string(&s);

                            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, "ping=1");
                            curl_easy_setopt(curl, CURLOPT_URL, buf);
                            curl_easy_setopt(curl, CURLOPT_USERAGENT, "Mozilla/5.0 (Windows NT 6.1; rv:60.0) Gecko/20100101 Firefox/60.0");

                            dbg(9, "request=%s", buf);

                            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writefunc);
                            curl_easy_setopt(curl, CURLOPT_WRITEDATA, &s);

                            res = curl_easy_perform(curl);

                            if (res != CURLE_OK)
                            {
                                dbg(9, "curl_easy_perform() failed: %s", curl_easy_strerror(res));
                            }
                            else
                            {
                                long http_code = 0;
                                curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
                                if ((http_code < 300) && (http_code > 199))
                                {
                                    dbg(9, "server_answer:OK:CURLINFO_RESPONSE_CODE=%ld, %s", http_code, s.ptr);
                                    result = 0;
                                }
                                else
                                {
                                    dbg(9, "server_answer:ERROR:CURLINFO_RESPONSE_CODE=%ld, %s", http_code, s.ptr);
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

    dbg(2, "Notification:Clean thread exit!");
    pthread_exit(0);
}

static void group_message_callback(Tox *tox, uint32_t groupnumber, uint32_t peer_number, TOX_MESSAGE_TYPE UNUSED(type),
                                   const uint8_t *message, size_t length, uint32_t message_id, void *UNUSED(userdata))
{
    dbg(0, "received group text message group:%d peer:%d", groupnumber, peer_number);

    uint8_t public_key_bin[TOX_GROUP_PEER_PUBLIC_KEY_SIZE];
    CLEAR(public_key_bin);
    Tox_Err_Group_Peer_Query error;
    bool res = tox_group_peer_get_public_key(tox, groupnumber, peer_number, public_key_bin, &error);

    if (res == false) {
        dbg(0, "received group text message from peer without pubkey?");
        return;
    } else {
        uint8_t group_id_buffer[TOX_GROUP_CHAT_ID_SIZE];
        CLEAR(group_id_buffer);
        bool res2 = tox_group_get_chat_id(tox, groupnumber, group_id_buffer, NULL);
        if (res2 == false) {
            dbg(0, "group id unknown?");
            return;
        } else {

            if (ping_push_service() == 1)
            {
                ping_push_service();
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
            dbg(0, "writeConferenceMessageGr:raw_message_len=%d length_m_text=%d", raw_message_len, (int)length_m_text);
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
            dbg(0, "writeConferenceMessageGr:msg_id_hex=%s", msg_id_hex);



            // ----------------------
            // ----------------------
            uint32_t rawMsgSize2 = tox_messagev2_size(raw_message_len, TOX_FILE_KIND_MESSAGEV2_SYNC, 0);
            uint8_t *raw_message2 = calloc(1, rawMsgSize2);
            uint8_t *msgid2 = calloc(1, TOX_PUBLIC_KEY_SIZE);
            tox_messagev2_sync_wrap(raw_message_len, group_id_buffer, TOX_FILE_KIND_MESSAGEV2_SEND,
                                    raw_message_data, 987, 775, raw_message2, msgid2);
            dbg(9, "send_sync_msg_single: wrapped raw message = %p TOX_FILE_KIND_MESSAGEV2_SEND", raw_message2);
            char msgid2_str[tox_public_key_hex_size + 1];
            CLEAR(msgid2_str);
            bin2upHex(msgid2, tox_public_key_size(), msgid2_str, tox_public_key_hex_size);
            dbg(9, "send_sync_msg_single:msgid2=%s msgid_orig=%s", msgid2_str, msg_id_hex);



            // -------
            char group_id_uhex[2*TOX_GROUP_CHAT_ID_SIZE + 1];
            B2UH(group_id_buffer, TOX_GROUP_CHAT_ID_SIZE, group_id_uhex);
            gm->groupid = csb(group_id_uhex);
            // -------
            dbg(0, "writeConferenceMessageGr:public_key_hex=%s", public_key_hex);
            gm->peerpubkey = csb(public_key_hex);
            // -------
            char group_msg_uhex[2*length + 1];
            B2UH(message, length, group_msg_uhex);
            gm->datahex = csb(group_msg_uhex);
            // -------
            char group_wrappedmsg_uhex[2*rawMsgSize2 + 1];
            B2UH(raw_message2, rawMsgSize2, group_wrappedmsg_uhex);
            gm->wrappeddatahex = csb(group_wrappedmsg_uhex);
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
            dbg(LOGLEVEL_INFO, "group_message inserted id: %lld\n", (long long)inserted_id);

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
        dbg(LOGLEVEL_ERROR, "tox_group_invite_accept failed");
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
    dbg(2, "Peer %d joined group %d", peer_id, group_number);
    updateToxSavedata(tox);
}

static void group_peer_exit_cb(Tox *tox, uint32_t group_number, uint32_t peer_id, Tox_Group_Exit_Type exit_type,
                                    const uint8_t *UNUSED(name), size_t UNUSED(name_length),
                                    const uint8_t *UNUSED(part_message), size_t UNUSED(length), void *UNUSED(user_data))
{
    switch (exit_type) {
        case TOX_GROUP_EXIT_TYPE_QUIT:
        dbg(2, "Peer %d left group %d reason: %d TOX_GROUP_EXIT_TYPE_QUIT", peer_id, group_number, exit_type);
            break;
        case TOX_GROUP_EXIT_TYPE_TIMEOUT:
        dbg(2, "Peer %d left group %d reason: %d TOX_GROUP_EXIT_TYPE_TIMEOUT", peer_id, group_number, exit_type);
            break;
        case TOX_GROUP_EXIT_TYPE_DISCONNECTED:
        dbg(2, "Peer %d left group %d reason: %d TOX_GROUP_EXIT_TYPE_DISCONNECTED", peer_id, group_number, exit_type);
            break;
        case TOX_GROUP_EXIT_TYPE_SELF_DISCONNECTED:
        dbg(2, "Peer %d left group %d reason: %d TOX_GROUP_EXIT_TYPE_SELF_DISCONNECTED", peer_id, group_number, exit_type);
            break;
        case TOX_GROUP_EXIT_TYPE_KICK:
        dbg(2, "Peer %d left group %d reason: %d TOX_GROUP_EXIT_TYPE_KICK", peer_id, group_number, exit_type);
            break;
        case TOX_GROUP_EXIT_TYPE_SYNC_ERROR:
        dbg(2, "Peer %d left group %d reason: %d TOX_GROUP_EXIT_TYPE_SYNC_ERROR", peer_id, group_number, exit_type);
            break;
    }
    updateToxSavedata(tox);
}

static void group_self_join_cb(Tox *tox, uint32_t group_number, void *UNUSED(user_data))
{
    dbg(2, "You joined group %d", group_number);
    updateToxSavedata(tox);
}

static void group_join_fail_cb(Tox *tox, uint32_t group_number, Tox_Group_Join_Fail fail_type, void *UNUSED(user_data))
{
    dbg(2, "Joining group %d failed. reason: %d", group_number, fail_type);
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
    dbg(2, "ToxProxy version: %s", global_version_string);

    mkdir(save_dir, S_IRWXU);
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

    read_token_from_file();

    on_start();

#if (NOTIFICATION_METHOD == NOTIFICATION_METHOD_GOTIFY_UP)
    curl_global_init(CURL_GLOBAL_ALL);
    need_send_notification = 0;
    notification_thread_stop = 0;

    if (pthread_create(&notification_thread, NULL, notification_thread_func, (void *)NULL) != 0)
    {
        dbg(0, "Notification Thread create failed");
    }
    else
    {
        pthread_setname_np(notification_thread, "t_notif");
        dbg(2, "Notification Thread successfully created");
    }
#endif

    Tox *tox = openTox();

    tox_public_key_hex_size = tox_public_key_size() * 2 + 1;
    tox_public_key_hex_size_without_null_termin = tox_public_key_size() * 2;
    tox_address_hex_size = tox_address_size() * 2 + 1;
    tox_address_hex_size_without_null_termin = tox_address_size() * 2;

    add_all_groups_to_db(tox);
    add_all_friends_to_db(tox);

    const char *name = "ToxProxy";
    tox_self_set_name(tox, (uint8_t *) name, strlen(name), NULL);

    const char *status_message = "Proxy for your messages";
    tox_self_set_status_message(tox, (uint8_t *) status_message, strlen(status_message), NULL);

    bootstrap(tox);

    uint8_t tox_id_bin[tox_address_size()];
    tox_self_get_address(tox, tox_id_bin);

    char toxid_hbuf[2*tox_address_size() + 1];
    B2UH(tox_id_bin, tox_address_size(), toxid_hbuf);

    // char toxid_binbuf[tox_address_size() + 1];
    // memset(toxid_binbuf, 0, tox_address_size() + 1);
    // H2B(toxid_hbuf, toxid_binbuf);

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
            dbg(LOGLEVEL_DEBUG, "inserted toxid: %lld", (long long)inserted_id);
        }
        orma_free_Self(p);
        }
    }
    else
    {
        dbg(LOGLEVEL_DEBUG, "updated toxid: %lld", (long long)affected_rows3);
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

    size_t friends = tox_self_get_friend_list_size(tox);
    dbg(9, "ToxProxy startup completed");
    dbg(9, "My Tox ID = %s", toxid_hbuf);
    dbg(9, "Number of friends = %ld", (long) friends);

    tox_callback_friend_request(tox, friend_request_cb);
    tox_callback_friend_message(tox, friend_message_cb);

#ifdef TOX_HAVE_TOXUTIL
    dbg(9, "using toxutil");
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
    dbg(9, "NOT using toxutil");
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
        dbg(LOGLEVEL_DEBUG, "pl->items=%lld\n", (long long)pl->items);
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
            dbg(2, "Tox online, took %llu seconds", time(NULL) - cur_time);

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
            dbg(2, "Tox NOT online yet, bootstrapping again");
            bootstrap(tox);

            if (try >= max_tries) {
                    dbg(1, "Tox NOT online for a long time, breaking bootstrap loop and starting iteration anyway.");

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
    pthread_setname_np(pthread_self(), "t_main");

    size_t num_friends = tox_self_get_friend_list_size(tox);
    dbg(2, "num_friends=%d", (int)num_friends);

    size_t num_conferences = tox_conference_get_chatlist_size(tox);
    dbg(2, "num_conferences=%d", (int)num_conferences);

    size_t num_groups = tox_group_get_number_groups(tox);
    dbg(2, "num_groups=%d", (int)num_groups);

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
                dbg(2, "Tox NOT online, bootstrapping again");
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
