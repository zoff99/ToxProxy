/*
 ============================================================================
 Name        : ToxProxy.c
 Authors     : Thomas Käfer, Zoff
 Copyright   : 2019 - 2021

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
#define VERSION_MAJOR 0
#define VERSION_MINOR 99
#define VERSION_PATCH 6
static const char global_version_string[] = "0.99.6";
// ----------- version -----------
// ----------- version -----------

// define this to use savedata file instead of included in sqlite
#define USE_SEPARATE_SAVEDATA_FILE

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
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <getopt.h>
#include <fcntl.h>
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <netdb.h>
#include <netinet/in.h>


#include <pthread.h>

#include <semaphore.h>
#include <signal.h>
#include <linux/sched.h>

// gives bin2hex & hex2bin functions for Tox-ID / public-key conversions
#include <sodium/utils.h>

// tox core
#include <tox/tox.h>

#undef TOX_HAVE_TOXUTIL
#define TOX_HAVE_TOXUTIL 1

#ifdef TOX_HAVE_TOXUTIL
#include <tox/toxutil.h>
#endif

// timestamps for printf output
#include <time.h>
#include <sys/time.h>

// mkdir -> https://linux.die.net/man/2/mkdir
#include <sys/stat.h>
#include <sys/types.h>

static char *NOTIFICATION__device_token = NULL;
static const char *NOTIFICATION_GOTIFY_UP_PREFIX = "https://";

#define NOTI__device_token_min_len 5
#define NOTI__device_token_max_len 300

#define NOTIFICATION_METHOD_NONE 0
#define NOTIFICATION_METHOD_TCP  1
#define NOTIFICATION_METHOD_HTTP 2
#define NOTIFICATION_METHOD_GOTIFY_UP 3

#define NOTIFICATION_METHOD NOTIFICATION_METHOD_GOTIFY_UP

#if NOTIFICATION_METHOD == NOTIFICATION_METHOD_HTTP
    #include "push_server_config.h"
#else
    #define PUSH__DST_PORT 1234
    #define PUSH__DST_HOST "127.0.0.1"
    #define PUSH__MAXDATASIZE 200
    #define HTTP_PUSH__DST_URL "https://127.0.0.1/notify"
#endif

#if NOTIFICATION_METHOD == NOTIFICATION_METHOD_HTTP
#include <curl/curl.h>
#endif

#if NOTIFICATION_METHOD == NOTIFICATION_METHOD_GOTIFY_UP
#include <curl/curl.h>
#endif

typedef struct DHT_node {
    const char *ip;
    uint16_t port;
    const char key_hex[TOX_PUBLIC_KEY_SIZE * 2 + 1];
    unsigned char key_bin[TOX_PUBLIC_KEY_SIZE];
} DHT_node;

#define CURRENT_LOG_LEVEL 50 // 0 -> error, 1 -> warn, 2 -> info, 9 -> debug
#define c_sleep(x) usleep_usec(1000*x)
#define CLEAR(x) memset(&(x), 0, sizeof(x))


typedef enum CONTROL_PROXY_MESSAGE_TYPE {
    CONTROL_PROXY_MESSAGE_TYPE_FRIEND_PUBKEY_FOR_PROXY = 175,
    CONTROL_PROXY_MESSAGE_TYPE_PROXY_PUBKEY_FOR_FRIEND = 176,
    CONTROL_PROXY_MESSAGE_TYPE_ALL_MESSAGES_SENT = 177,
    CONTROL_PROXY_MESSAGE_TYPE_PROXY_KILL_SWITCH = 178,
    CONTROL_PROXY_MESSAGE_TYPE_NOTIFICATION_TOKEN = 179
} CONTROL_PROXY_MESSAGE_TYPE;

FILE *logfile = NULL;
#ifndef UNIQLOGFILE
const char *log_filename = "toxblinkenwall.log";
#endif

#ifdef USE_SEPARATE_SAVEDATA_FILE
const char *savedata_filename = "./db/savedata.tox";
const char *savedata_tmp_filename = "./db/savedata.tox.tmp";
#endif

const char *empty_log_message = "empty log message received!";
const char *msgsDir = "./messages";
const char *masterFile = "./db/toxproxymasterpubkey.txt";
const char *tokenFile = "./db/token.txt";

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

uint32_t tox_public_key_hex_size = 0; //initialized in main
uint32_t tox_address_hex_size = 0; //initialized in main
int tox_loop_running = 1;
bool masterIsOnline = false;

pthread_t notification_thread;
int notification_thread_stop = 1;
int need_send_notification = 0;

int ping_push_service();

void openLogFile()
{
// gcc parameter -DUNIQLOGFILE for logging to standardout = console
#ifdef UNIQLOGFILE
    struct timeval tv;
    gettimeofday(&tv, NULL);
    struct tm tm = *localtime(&tv.tv_sec);

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

void toxProxyLog(int level, const char *msg, ...)
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
        case 0:
            buffer[28] = 'E';
            break;

        case 1:
            buffer[28] = 'W';
            break;

        case 2:
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

void tox_log_cb__custom(Tox *tox, TOX_LOG_LEVEL level, const char *file, uint32_t line, const char *func,
                        const char *message, void *user_data)
{
    toxProxyLog(9, "ToxCore LogMsg: [%d] %s:%d - %s:%s", (int) level, file, (int) line, func, message);
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
    toxProxyLog(2, "got killSwitch command, deleting all data");
#ifdef USE_SEPARATE_SAVEDATA_FILE
    unlink(savedata_filename);
#endif
    unlink(masterFile);
    unlink(tokenFile);
    toxProxyLog(1, "todo implement deleting messages");
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


#ifndef USE_SEPARATE_SAVEDATA_FILE
// https://www.tutorialspoint.com/sqlite/sqlite_c_cpp
#include <sqlite3.h>

const char *database_filename = "ToxProxy.db";

void dbInsertMsg()
{
    sqlite3 *db;
    sqlite3_stmt *stmt;
    char *sql = \
                "CREATE TABLE IF NOT EXISTS Messages(" \
                "id INTEGER PRIMARY KEY AUTOINCREMENT" \
                ",received DATETIME" \
                ",forwarded DATETIME" \
                ",confirmation_received DATETIME" \
                ",rawMsg BLOB NOT NULL);";
}

void sqlite_createSaveDataTable(sqlite3 *db)
{

    const char *sql = \
                      "CREATE TABLE ToxCoreSaveData(" \
                      "id INTEGER PRIMARY KEY," \
                      "data BLOB NOT NULL);";

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, 0);

    if (rc != SQLITE_OK) {
        toxProxyLog(0, "sqlite_createSaveDataTable - Failed to prepare create tbl stmt: %s", sqlite3_errmsg(db));
        sqlite3_close(db);
        exit(1);
    }

    rc = sqlite3_step(stmt);
    toxProxyLog(9, "sqlite_createSaveDataTable rc of step = %d", rc);
    rc = sqlite3_finalize(stmt);
    toxProxyLog(9, "sqlite_createSaveDataTable rc of finalize = %d", rc);
}


typedef struct SizedSavedata {
    const uint8_t *savedata;
    size_t savedataSize;
    sqlite3 *db;
    sqlite3_stmt *stmt;
} SizedSavedata;

SizedSavedata dbSavedataAction(bool putData, const uint8_t *savedata, size_t savedataSize)
{
    sqlite3 *db;
    sqlite3_stmt *stmt;
    char *sql = "SELECT COUNT(*) FROM ToxCoreSaveData";
    int rowCount = -1;

    int rc = sqlite3_open(database_filename, &db);

    if (rc != SQLITE_OK) {
        toxProxyLog(0, "dbSavedataAction - Cannot open database: %s", sqlite3_errmsg(db));
        sqlite3_close(db);
        exit(1);
    }

    sqlite3_busy_timeout(db, 2000);

    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, 0);

    if (rc != SQLITE_OK) {
        const char *errorMsg = sqlite3_errmsg(db);

        if (strncmp("no such table: ToxCoreSaveData", errorMsg, 30) == 0) {
            toxProxyLog(1, "dbSavedataAction - savedata table doesn't exist (first run?), create if it data insertion is planned!");
            sqlite_createSaveDataTable(db);
            rc = sqlite3_prepare_v2(db, sql, -1, &stmt, 0);

            if (rc != SQLITE_OK) {
                toxProxyLog(0, "dbSavedataAction - Failed to prepare row count data stmt even after creating table. errormsg: %s",
                            sqlite3_errmsg(db));
                sqlite3_close(db);
                exit(1);
            }
        } else {
            toxProxyLog(0, "dbSavedataAction - Failed to prepare row count data stmt: %s", errorMsg);
            sqlite3_close(db);
            exit(1);
        }

    }

    rc = sqlite3_step(stmt);

    if (rc == SQLITE_ROW) {
        rowCount = sqlite3_column_int(stmt, 0);
        toxProxyLog(9, "dbSavedataAction received count result: %d", rowCount); //, sqlite3_column_text(stmt, 0));
    } else {
        toxProxyLog(0, "dbSavedataAction received something different than a count result. rc = %d, error = %s", rc,
                    sqlite3_errmsg(db));
        exit(1);
    }

    rc = sqlite3_finalize(stmt);
    toxProxyLog(9, "dbSavedataAction rc of rowcount stmt finalize = %d", rc);

    if (!(rowCount == 0 || rowCount == 1)) {
        toxProxyLog(0, "dbSavedataAction failed because rowCount is unexpected: %d", rowCount);
        sqlite3_close(db);
        exit(1);
    }

    if (putData) {
        if (rowCount == 0) {
            sql = "INSERT INTO ToxCoreSaveData(data) VALUES(?)";
        } else {
            sql = "UPDATE ToxCoreSaveData SET data = ?";
        }
    } else {
        if (rowCount == 0) {
            toxProxyLog(1, "dbSavedataAction: can't load data because savedata table is empty (first run!).");
            sqlite3_close(db);
            SizedSavedata empty = {NULL, 0, NULL, NULL};
            return empty;
        } else {
            sql = "SELECT data FROM ToxCoreSaveData";
        }
    }

    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, 0);

    if (rc != SQLITE_OK) {
        toxProxyLog(0, "dbSavedataAction - Failed to prepare savedata insert/update/select stmt: %s", sqlite3_errmsg(db));
        sqlite3_close(db);
        exit(1);
    }

    if (putData) {
        rc = sqlite3_bind_blob(stmt, 1, savedata, savedataSize, SQLITE_STATIC);

        if (rc != SQLITE_OK) {
            toxProxyLog(0, "sqlite3 insert savedata - bind failed: %s", sqlite3_errmsg(db));
        } else {
            rc = sqlite3_step(stmt);

            if (rc != SQLITE_DONE) {
                toxProxyLog(0, "sqlite3 insert savedata - execution failed: %s", sqlite3_errmsg(db));
            }
        }
    } else {
        rc = sqlite3_step(stmt);

        if (rc == SQLITE_ROW) {
            savedataSize = sqlite3_column_bytes(stmt, 0);
            savedata = sqlite3_column_blob(stmt,
                                           0); //gives "discards 'const' qualifier"-warning but works. maybe Zoff can suggest improvement?
            SizedSavedata data = {savedata, savedataSize, db, stmt};
            return data;
        } else {
            toxProxyLog(0,
                        "dbSavedataAction select savedata received something different than the expected blob. rc = %d, error = %s", rc,
                        sqlite3_errmsg(db));
            sqlite3_close(db);
            exit(1);
        }
    }

    sqlite3_close(db);
    SizedSavedata empty = {NULL, 0, NULL, NULL};
    return empty;
}
#endif


void updateToxSavedata(const Tox *tox)
{
    size_t size = tox_get_savedata_size(tox);
    uint8_t *savedata = calloc(1, size);
    tox_get_savedata(tox, savedata);

#ifdef USE_SEPARATE_SAVEDATA_FILE
    FILE *f = fopen(savedata_tmp_filename, "wb");
    fwrite(savedata, size, 1, f);
    fclose(f);

    rename(savedata_tmp_filename, savedata_filename);
#else
    dbSavedataAction(true, savedata, size);
#endif

    free(savedata);
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

    // set our own handler for c-toxcore logging messages!!
    options.log_callback = tox_log_cb__custom;

#ifdef USE_SEPARATE_SAVEDATA_FILE
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

#else
    SizedSavedata ssd = dbSavedataAction(false, NULL, 0);

    if (ssd.savedataSize != 0) {
        options.savedata_type = TOX_SAVEDATA_TYPE_TOX_SAVE;
        options.savedata_data = ssd.savedata;
        options.savedata_length = ssd.savedataSize;
    }

#endif

#ifdef TOX_HAVE_TOXUTIL
    tox = tox_utils_new(&options, NULL);
#else
    tox = tox_new(&options, NULL);
#endif

#ifdef USE_SEPARATE_SAVEDATA_FILE
    free(savedata);
#else
    sqlite3_finalize(ssd.stmt);
    sqlite3_close(ssd.db);
#endif
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
        toxProxyLog(99, "bootstap_nodes - sodium_hex2bin:res=%d", res);
        TOX_ERR_BOOTSTRAP error;
        res = tox_bootstrap(tox, nodes[i].ip, nodes[i].port, nodes[i].key_bin, &error);

        if (res != true) {
            if (error == TOX_ERR_BOOTSTRAP_OK) {
//              toxProxyLog(9, "bootstrap:%s %d [FALSE]res=TOX_ERR_BOOTSTRAP_OK\n", nodes[i].ip, nodes[i].port);
            } else if (error == TOX_ERR_BOOTSTRAP_NULL) {
//              toxProxyLog(9, "bootstrap:%s %d [FALSE]res=TOX_ERR_BOOTSTRAP_NULL\n", nodes[i].ip, nodes[i].port);
            } else if (error == TOX_ERR_BOOTSTRAP_BAD_HOST) {
//              toxProxyLog(9, "bootstrap:%s %d [FALSE]res=TOX_ERR_BOOTSTRAP_BAD_HOST\n", nodes[i].ip, nodes[i].port);
            } else if (error == TOX_ERR_BOOTSTRAP_BAD_PORT) {
//              toxProxyLog(9, "bootstrap:%s %d [FALSE]res=TOX_ERR_BOOTSTRAP_BAD_PORT\n", nodes[i].ip, nodes[i].port);
            }
        } else {
//          toxProxyLog(9, "bootstrap:%s %d [TRUE]res=%d\n", nodes[i].ip, nodes[i].port, res);
        }

        if (add_as_tcp_relay == 1) {
            res = tox_add_tcp_relay(tox, nodes[i].ip, nodes[i].port, nodes[i].key_bin, &error); // use also as TCP relay

            if (res != true) {
                if (error == TOX_ERR_BOOTSTRAP_OK) {
//                  toxProxyLog(9, "add_tcp_relay:%s %d [FALSE]res=TOX_ERR_BOOTSTRAP_OK\n", nodes[i].ip, nodes[i].port);
                } else if (error == TOX_ERR_BOOTSTRAP_NULL) {
//                  toxProxyLog(9, "add_tcp_relay:%s %d [FALSE]res=TOX_ERR_BOOTSTRAP_NULL\n", nodes[i].ip, nodes[i].port);
                } else if (error == TOX_ERR_BOOTSTRAP_BAD_HOST) {
//                  toxProxyLog(9, "add_tcp_relay:%s %d [FALSE]res=TOX_ERR_BOOTSTRAP_BAD_HOST\n", nodes[i].ip, nodes[i].port);
                } else if (error == TOX_ERR_BOOTSTRAP_BAD_PORT) {
//                  toxProxyLog(9, "add_tcp_relay:%s %d [FALSE]res=TOX_ERR_BOOTSTRAP_BAD_PORT\n", nodes[i].ip, nodes[i].port);
                }
            } else {
//              toxProxyLog(9, "add_tcp_relay:%s %d [TRUE]res=%d\n", nodes[i].ip, nodes[i].port, res);
            }
        } else {
//            toxProxyLog(2, "Not adding any TCP relays\n");
        }
    }
}

void bootstrap(Tox *tox)
{

    DHT_node bootstrap_nodes[] = {
            {"85.172.30.117",33445,"8E7D0B859922EF569298B4D261A8CCB5FEA14FB91ED412A7603A585A25698832", {0}},
            {"85.143.221.42",33445,"DA4E4ED4B697F2E9B000EEFE3A34B554ACD3F45F5C96EAEA2516DD7FF9AF7B43", {0}},
            {"tox.verdict.gg",33445,"1C5293AEF2114717547B39DA8EA6F1E331E5E358B35F9B6B5F19317911C5F976", {0}},
            {"78.46.73.141",33445,"02807CF4F8BB8FB390CC3794BDF1E8449E9A8392C5D3F2200019DA9F1E812E46", {0}},
            {"tox.initramfs.io",33445,"3F0A45A268367C1BEA652F258C85F4A66DA76BCAA667A49E770BCC4917AB6A25", {0}},
            {"46.229.52.198",33445,"813C8F4187833EF0655B10F7752141A352248462A567529A38B6BBF73E979307", {0}},
            {"144.217.167.73",33445,"7E5668E0EE09E19F320AD47902419331FFEE147BB3606769CFBE921A2A2FD34C", {0}},
            {"tox.abilinski.com",33445,"10C00EB250C3233E343E2AEBA07115A5C28920E9C8D29492F6D00B29049EDC7E", {0}},
            {"tox.novg.net",33445,"D527E5847F8330D628DAB1814F0A422F6DC9D0A300E6C357634EE2DA88C35463", {0}},
            {"95.31.18.227",33445,"257744DBF57BE3E117FE05D145B5F806089428D4DCE4E3D0D50616AA16D9417E", {0}},
            {"198.199.98.108",33445,"BEF0CFB37AF874BD17B9A8F9FE64C75521DB95A37D33C5BDB00E9CF58659C04F", {0}},
            {"tox.kurnevsky.net",33445,"82EF82BA33445A1F91A7DB27189ECFC0C013E06E3DA71F588ED692BED625EC23", {0}},
            {"81.169.136.229",33445,"E0DB78116AC6500398DDBA2AEEF3220BB116384CAB714C5D1FCD61EA2B69D75E", {0}},
            {"205.185.115.131",53,"3091C6BEB2A993F1C6300C16549FABA67098FF3D62C6D253828B531470B53D68", {0}},
            {"205.185.115.131",443,"3091C6BEB2A993F1C6300C16549FABA67098FF3D62C6D253828B531470B53D68", {0}},
            {"tox2.abilinski.com",33445,"7A6098B590BDC73F9723FC59F82B3F9085A64D1B213AAF8E610FD351930D052D", {0}},
            {"floki.blog",33445,"6C6AF2236F478F8305969CCFC7A7B67C6383558FF87716D38D55906E08E72667", {0}},
            {"46.101.197.175",33445,"CD133B521159541FB1D326DE9850F5E56A6C724B5B8E5EB5CD8D950408E95707", {0}},
            {"tox1.mf-net.eu",33445,"B3E5FA80DC8EBD1149AD2AB35ED8B85BD546DEDE261CA593234C619249419506", {0}},
            {"tox2.mf-net.eu",33445,"70EA214FDE161E7432530605213F18F7427DC773E276B3E317A07531F548545F", {0}},
            {"46.146.229.184",33445,"94750E94013586CCD989233A621747E2646F08F31102339452CADCF6DC2A760A", {0}},
            {"195.201.7.101",33445,"B84E865125B4EC4C368CD047C72BCE447644A2DC31EF75BD2CDA345BFD310107", {0}},
            {"168.138.203.178",33445,"6D04D8248E553F6F0BFDDB66FBFB03977E3EE54C432D416BC2444986EF02CC17", {0}},
            {"5.19.249.240",38296,"DA98A4C0CD7473A133E115FEA2EBDAEEA2EF4F79FD69325FC070DA4DE4BA3238", {0}},
            {"209.59.144.175",33445,"214B7FEA63227CAEC5BCBA87F7ABEEDB1A2FF6D18377DD86BF551B8E094D5F1E", {0}},
            {"188.225.9.167",33445,"098AD1859B0F29894C49DBD108689432047F79CE57DD2BBDAD2E638C85521F2E", {0}},
            {"122.116.39.151",33445,"5716530A10D362867C8E87EE1CD5362A233BAFBBA4CF47FA73B7CAD368BD5E6E", {0}},
            {"195.123.208.139",33445,"534A589BA7427C631773D13083570F529238211893640C99D1507300F055FE73", {0}},
            {"208.38.228.104",33445,"3634666A51CA5BE1579C031BD31B20059280EB7C05406ED466BD9DFA53373271", {0}},
            {"lunarfire.spdns.org",33445,"E61F5963268A6306CCFE7AF98716345235763529957BD5F45889484654EE052B", {0}}
    };


#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wall"
    bootstap_nodes(tox, bootstrap_nodes, (int)(sizeof(bootstrap_nodes) / sizeof(DHT_node)), 1);
#pragma GCC diagnostic pop

}

void writeConferenceMessage(Tox *tox, const char *sender_key_hex, const uint8_t *message_orig, size_t length_orig,
                            uint32_t msg_type, char *peer_pubkey_hex)
{
    size_t length = length_orig + 64;
    size_t len_copy = length_orig;

    if (length > TOX_MAX_MESSAGE_LENGTH) {
        length = TOX_MAX_MESSAGE_LENGTH;
        len_copy = TOX_MAX_MESSAGE_LENGTH - (TOX_MAX_MESSAGE_LENGTH - (length_orig + 64));
    }

    uint8_t *message = calloc(1, length);
    // put peer pubkey in front of message
    memcpy(message, peer_pubkey_hex, 64);
    // put message after peer pubkey
    memcpy(message + 64, message_orig, len_copy);

    uint32_t raw_message_len = tox_messagev2_size(length, TOX_FILE_KIND_MESSAGEV2_SEND, 0);

    toxProxyLog(0, "writeConferenceMessage:raw_message_len=%d length=%d", raw_message_len, (int)length);
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
    toxProxyLog(0, "writeConferenceMessage:msg_id_hex=%s", msg_id_hex);

    char userDir[tox_public_key_hex_size + strlen(msgsDir) + 1];
    CLEAR(userDir);

    strcpy(userDir, msgsDir);
    strcat(userDir, "/");
    strcat(userDir, sender_key_hex);

    mkdir(msgsDir, S_IRWXU);
    mkdir(userDir, S_IRWXU);

    //TODO FIXME use message v2 message id / hash instead of timestamp of receiving / processing message!

    char timestamp[strlen("0000-00-00_0000-00,000000") + 1]; // = "0000-00-00_0000-00,000000";
    CLEAR(timestamp);

    struct timeval tv;
    gettimeofday(&tv, NULL);
    struct tm tm = *localtime(&tv.tv_sec);
    snprintf(timestamp, sizeof(timestamp), "%04d-%02d-%02d_%02d%02d-%02d,%06ld",
             tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, tv.tv_usec);

    char *msgPath = calloc(1, sizeof(userDir) + 1 + sizeof(timestamp) + 4 + 1);
    strcpy(msgPath, userDir);
    strcat(msgPath, "/");
    strcat(msgPath, timestamp);
    strcat(msgPath, ".txtS");

    FILE *f = fopen(msgPath, "wb");

    if (f) {
        fwrite(raw_message_data, raw_message_len, 1, f);
        fclose(f);
    }

    if (ping_push_service() == 1)
    {
        ping_push_service();
    }

    free(raw_message_data);
    free(message);
    free(msgPath);
}

void writeMessage(char *sender_key_hex, const uint8_t *message, size_t length, uint32_t msg_type)
{

    uint8_t *msg_id = calloc(1, tox_public_key_size());
    tox_messagev2_get_message_id(message, msg_id);
    toxProxyLog(2, "New message from %s msg_type=%d", sender_key_hex, msg_type);

    char userDir[tox_public_key_hex_size + strlen(msgsDir) + 1];
    CLEAR(userDir);

    strcpy(userDir, msgsDir);
    strcat(userDir, "/");
    strcat(userDir, sender_key_hex);

    mkdir(msgsDir, S_IRWXU);
    mkdir(userDir, S_IRWXU);

    //TODO FIXME use message v2 message id / hash instead of timestamp of receiving / processing message!

    char timestamp[strlen("0000-00-00_0000-00,000000") + 1]; // = "0000-00-00_0000-00,000000";
    CLEAR(timestamp);

    struct timeval tv;
    gettimeofday(&tv, NULL);
    struct tm tm = *localtime(&tv.tv_sec);
    snprintf(timestamp, sizeof(timestamp), "%04d-%02d-%02d_%02d%02d-%02d,%06ld",
             tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, tv.tv_usec);

    char *msgPath = calloc(1, sizeof(userDir) + 1 + sizeof(timestamp) + 4 + 1);
    strcpy(msgPath, userDir);
    strcat(msgPath, "/");
    strcat(msgPath, timestamp);

    if (msg_type == TOX_FILE_KIND_MESSAGEV2_ANSWER) {
        strcat(msgPath, ".txtA");
    } else if (msg_type == TOX_FILE_KIND_MESSAGEV2_SEND) {
        strcat(msgPath, ".txtS");
    }

    FILE *f = fopen(msgPath, "wb");

    if (f) {
        fwrite(message, length, 1, f);
        fclose(f);
    }

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
                                  char *peer_pubkey_hex)
{
    char conference_id_hex[TOX_CONFERENCE_ID_SIZE * 2 + 1];
    CLEAR(conference_id_hex);

    bin2upHex(conference_id, TOX_CONFERENCE_ID_SIZE, conference_id_hex, (TOX_CONFERENCE_ID_SIZE * 2 + 1));
    writeConferenceMessage(tox, conference_id_hex, message, length, TOX_FILE_KIND_MESSAGEV2_SEND, peer_pubkey_hex);
}

bool file_exists(const char *path)
{
    struct stat s;
    return stat(path, &s) == 0;
}

// fill string with toxid in upper case hex.
// size of toxid_str needs to be: [TOX_ADDRESS_SIZE*2 + 1] !!
void get_my_toxid(Tox *tox, char *toxid_str)
{
    uint8_t tox_id_bin[TOX_ADDRESS_SIZE];
    CLEAR(tox_id_bin);

    tox_self_get_address(tox, tox_id_bin);
    char tox_id_hex_local[TOX_ADDRESS_SIZE * 2 + 1];
    CLEAR(tox_id_hex_local);

    sodium_bin2hex(tox_id_hex_local, sizeof(tox_id_hex_local), tox_id_bin, sizeof(tox_id_bin));

    for (size_t i = 0; i < sizeof(tox_id_hex_local) - 1; i ++) {
        tox_id_hex_local[i] = toupper(tox_id_hex_local[i]);
    }

    snprintf(toxid_str, (size_t)(TOX_ADDRESS_SIZE * 2 + 1), "%s", (const char *)tox_id_hex_local);
}

void add_master(const char *public_key_hex)
{

    if (file_exists(masterFile)) {
        toxProxyLog(2, "I already have a *MASTER*");
        return;
    }

    toxProxyLog(2, "added master");

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
        toxProxyLog(2, "Tokenfile already exists, deleting it");
        unlink(tokenFile);
    }

    FILE *f = fopen(tokenFile, "wb");

    if (f) {
        fwrite(token_str, strlen(token_str), 1, f);
        fprintf(stdout, "saved token:%s\n", NOTIFICATION__device_token);
        toxProxyLog(2, "saved token:%s\n", NOTIFICATION__device_token);
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
    toxProxyLog(2, "loaded token:%s\n", NOTIFICATION__device_token);

    fclose(f);
}

bool is_master(const char *public_key_hex)
{
    //toxProxyLog(2, "enter:is_master");

    if (!file_exists(masterFile)) {
        toxProxyLog(2, "master file does not exist");
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

    char *masterPubKeyHexSaved = calloc(1, fsize);
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

void getPubKeyHex_friendnumber(Tox *tox, uint32_t friend_number, char *pubKeyHex)
{
    uint8_t public_key_bin[tox_public_key_size()];
    CLEAR(public_key_bin);
    tox_friend_get_public_key(tox, friend_number, public_key_bin, NULL);
    bin2upHex(public_key_bin, tox_public_key_size(), pubKeyHex, tox_public_key_hex_size);
}

bool is_master_friendnumber(Tox *tox, uint32_t friend_number)
{
    bool ret = false;
    char *pubKeyHex = calloc(1, tox_public_key_hex_size);
    getPubKeyHex_friendnumber(tox, friend_number, pubKeyHex);
    ret = is_master(pubKeyHex);
    free(pubKeyHex);
    return ret;
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

void friend_request_cb(Tox *tox, const uint8_t *public_key, const uint8_t *message, size_t length, void *user_data)
{
    char public_key_hex[tox_public_key_hex_size];
    CLEAR(public_key_hex);
    bin2upHex(public_key, tox_public_key_size(), public_key_hex, tox_public_key_hex_size);

    size_t friends = tox_self_get_friend_list_size(tox);

    if (friends == 0) {
        // add first friend as master for this proxy
        add_master(public_key_hex);
        tox_friend_add_norequest(tox, public_key, NULL);
        updateToxSavedata(tox);
    } else {
        // once I have a master, I don't add friend's on request, only by command of my master!
        return;
    }

    toxProxyLog(2, "Got currently %zu friends. New friend request from %s with message: %s",
                friends, public_key_hex, message);

    friends = tox_self_get_friend_list_size(tox);
    toxProxyLog(2, "Added friend: %s. Number of total friends: %zu", public_key_hex, friends);
}

void friend_message_cb(Tox *tox, uint32_t friend_number, TOX_MESSAGE_TYPE type, const uint8_t *message, size_t length,
                       void *user_data)
{
    // char *default_msg = "YOU are using the old Message format! this is not supported!";
    // tox_friend_send_message(tox, friend_number, type, (uint8_t *) default_msg, strlen(default_msg), NULL);

    toxProxyLog(2, "YOU are using the old Message: fnum=%d", friend_number);
}

//
// cut message at 999 chars length !!
//
void send_text_message_to_friend(Tox *tox, uint32_t friend_number, const char *fmt, ...)
{
    toxProxyLog(9, "sending message to friend %d", friend_number);
    char msg2[1000];
    CLEAR(msg2);
    size_t length = 0;

    if (fmt == NULL) {
        toxProxyLog(9, "send_text_message_to_friend:no message to send");
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

void friendlist_onConnectionChange(Tox *tox, uint32_t friend_number, TOX_CONNECTION connection_status, void *user_data)
{

    toxProxyLog(2, "friendlist_onConnectionChange:*READY*:friendnum=%d %d", (int) friend_number, (int) connection_status);

    if (is_master_friendnumber(tox, friend_number)) {
        if (connection_status != TOX_CONNECTION_NONE) {
            toxProxyLog(2, "master is online, send him all cached unsent messages");
            masterIsOnline = true;
        } else {
            toxProxyLog(2, "master went offline, don't send him any more messages.");
            masterIsOnline = false;
        }
    }
}

void self_connection_status_cb(Tox *tox, TOX_CONNECTION connection_status, void *user_data)
{
    switch (connection_status) {
        case TOX_CONNECTION_NONE:
            toxProxyLog(2, "Connection Status changed to: Offline");
            fprintf(stdout, "Connection Status changed to:Offline\n");
            my_connection_status = TOX_CONNECTION_NONE;
            on_offline();
            break;

        case TOX_CONNECTION_TCP:
            toxProxyLog(2, "Connection Status changed to: Online via TCP");
            fprintf(stdout, "Connection Status changed to:Online via TCP\n");
            my_connection_status = TOX_CONNECTION_TCP;
            on_online();
            break;

        case TOX_CONNECTION_UDP:
            toxProxyLog(2, "Connection Status changed to: Online via UDP");
            fprintf(stdout, "Connection Status changed to:Online via UDP\n");
            my_connection_status = TOX_CONNECTION_UDP;
            on_online();
            break;
    }
}

void conference_invite_cb(Tox *tox, uint32_t friend_number, TOX_CONFERENCE_TYPE type, const uint8_t *cookie,
                          size_t length, void *user_data)
{
    if (!is_master_friendnumber(tox, friend_number)) {
        toxProxyLog(0, "received conference invite from somebody who's not master!");
        return;
    }

    toxProxyLog(0, "received conference invite from fnum:%d", friend_number);
    long conference_num = tox_conference_join(tox, friend_number, cookie, length, NULL);

    toxProxyLog(0, "received conference join: res=%d", (int)conference_num);

    updateToxSavedata(tox);
}

void conference_message_cb(Tox *tox, uint32_t conference_number, uint32_t peer_number, TOX_MESSAGE_TYPE type,
                           const uint8_t *message, size_t length, void *user_data)
{
    toxProxyLog(0, "received conference text message conf:%d peer:%d", conference_number, peer_number);

    uint8_t public_key_bin[TOX_PUBLIC_KEY_SIZE];
    CLEAR(public_key_bin);
    TOX_ERR_CONFERENCE_PEER_QUERY error;
    bool res = tox_conference_peer_get_public_key(tox, conference_number, peer_number, public_key_bin, &error);

    if (res == false) {
        toxProxyLog(0, "received conference from peer without pubkey?");
        return;
    } else {
        char public_key_hex[tox_public_key_hex_size];
        CLEAR(public_key_hex);
        bin2upHex(public_key_bin, tox_public_key_size(), public_key_hex, tox_public_key_hex_size);

        if (is_master(public_key_hex)) {
            toxProxyLog(0, "received conference text message from master");
        } else {
            uint8_t conference_id_buffer[TOX_CONFERENCE_ID_SIZE + 1];
            CLEAR(conference_id_buffer);
            bool res2 = tox_conference_get_id(tox, conference_number, conference_id_buffer);

            if (res2 == false) {
                toxProxyLog(0, "conference id unknown?");
                return;
            } else {
                writeConferenceMessageHelper(tox, conference_id_buffer, message, length, public_key_hex);
            }
        }
    }
}

void conference_peer_list_changed_cb(Tox *tox, uint32_t conference_number, void *user_data)
{
    updateToxSavedata(tox);
}

void friend_sync_message_v2_cb(Tox *tox, uint32_t friend_number, const uint8_t *message, size_t length)
{
    toxProxyLog(9, "enter friend_sync_message_v2_cb");
}

bool is_answer_to_synced_message(Tox *tox, uint32_t friend_number, const uint8_t *message, size_t length)
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

        toxProxyLog(2, "is_answer_to_synced_message: receipt from %s id __%s__", public_key_hex, msgid2_str);

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

                    char *friendDir = calloc(1, strlen(msgsDir) + 1 + strlen(dp_m->d_name) + 1);
                    sprintf(friendDir, "%s/%s", msgsDir, dp_m->d_name);

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
                                int len = strlen(dp->d_name);
                                const char *last_char = &dp->d_name[len - 1];
                                if (strncmp(last_char, "_", 1) == 0)
                                {
                                    const char *last_char2 = &dp->d_name[len - END_PART_GLOB_LEN];
                                    char *comp_str = calloc(1, (END_PART_GLOB_LEN + 2));
                                    sprintf(comp_str, "__%s__", msgid2_str);

                                    if (strncmp(last_char2, comp_str, END_PART_GLOB_LEN) == 0)
                                    {
                                        toxProxyLog(2, "is_answer_to_synced_message: found id %s in %s", comp_str, dp->d_name);
                                        // now delete all files for that id
                                        char *delete_file_glob = calloc(1, 1000);
                                        int ret_snprintf = snprintf(delete_file_glob, BASE_NAME_GLOB_LEN, "%s", dp->d_name);
                                        if (ret_snprintf){}
                                        char *run_cmd = calloc(1, 1000);
                                        sprintf(run_cmd, "rm %s/%s*", friendDir, delete_file_glob);
                                        toxProxyLog(2, "is_answer_to_synced_message: running cmd: %s", run_cmd);
                                        int cmd_res = system(run_cmd);
                                        if (cmd_res){}
                                        toxProxyLog(2, "is_answer_to_synced_message: cmd DONE");
                                        free(run_cmd);
                                        free(delete_file_glob);

                                        free(comp_str);

                                        ret = true;
                                    }
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
    toxProxyLog(9, "enter friend_read_receipt_message_v2_cb");

	// check if the received msg is confirm conference msg received
	// todo: when sending cached msgs to master: don't delete them instantly, instead only delete them here, if the receipt message's id is equal to one of the stored ones.
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
    }
    else
    {
        writeMessageHelper(tox, friend_number, raw_message_data, raw_message_len, TOX_FILE_KIND_MESSAGEV2_ANSWER);
    }

#endif

}

void friend_message_v2_cb(Tox *tox, uint32_t friend_number, const uint8_t *raw_message, size_t raw_message_len)
{

    toxProxyLog(9, "enter friend_message_v2_cb");

#ifdef TOX_HAVE_TOXUTIL
    // now get the real data from msgV2 buffer
    uint8_t *message_text = calloc(1, raw_message_len);

    if (message_text) {
        // uint32_t ts_sec = tox_messagev2_get_ts_sec(raw_message);
        // uint16_t ts_ms = tox_messagev2_get_ts_ms(raw_message);
        uint32_t text_length = 0;
        bool res = tox_messagev2_get_message_text(raw_message, (uint32_t) raw_message_len, (bool) false, (uint32_t) 0,
                   message_text, &text_length);
        toxProxyLog(9, "friend_message_v2_cb:fn=%d res=%d msg=%s", (int) friend_number, (int) res, (char *) message_text);

        if (is_master_friendnumber(tox, friend_number)) {
            if ((strlen((char *) message_text) == (strlen("fp:") + tox_public_key_hex_size))
                    &&
                    (strncmp((char *) message_text, "fp:", strlen("fp:")))) {
                char *pubKey = (char *)(message_text + 3);
                uint8_t public_key_bin[tox_public_key_size()];
                hex_string_to_bin(pubKey, tox_public_key_size() * 2, (char *) public_key_bin, tox_public_key_size());
                tox_friend_add_norequest(tox, public_key_bin, NULL);
                updateToxSavedata(tox);
            } else if (strlen((char *) message_text) == strlen("DELETE_EVERYTHING")
                       && strncmp((char *) message_text, "DELETE_EVERYTHING", strlen("DELETE_EVERYTHING"))) {
                killSwitch();
            } else {
                // send_text_message_to_friend(tox, friend_number, "Sorry, but this command has not been understood, please check the implementation or contact the developer.");
            }
        } else {
            toxProxyLog(9, "call writeMessageHelper()");
            // nicht vom master, also wohl ein freund vom master.

            // save the message to storage
            writeMessageHelper(tox, friend_number, raw_message, raw_message_len, TOX_FILE_KIND_MESSAGEV2_SEND);

            // send back an ACK, that toxproxy has received the message
            if (raw_message_len >= TOX_PUBLIC_KEY_SIZE)
            {
                uint8_t *msgid_acked = calloc(1, TOX_PUBLIC_KEY_SIZE);
                memcpy(msgid_acked, raw_message, TOX_PUBLIC_KEY_SIZE);
                tox_util_friend_send_msg_receipt_v2(tox, friend_number, msgid_acked, 0);
            }
        }

        free(message_text);
    }

#endif
}

void friend_lossless_packet_cb(Tox *tox, uint32_t friend_number, const uint8_t *data, size_t length, void *user_data)
{

    if (length == 0) {
        toxProxyLog(0, "received empty lossless package!");
        return;
    }

    if (!is_master_friendnumber(tox, friend_number)) {
        if (length > 0)
        {
            toxProxyLog(0, "received lossless package from somebody who's not master! : id=%d", (int)data[0]);
        }
        else
        {
            toxProxyLog(0, "received lossless package from somebody who's not master!");
        }
        return;
    }

    if (data[0] == CONTROL_PROXY_MESSAGE_TYPE_PROXY_KILL_SWITCH) {
        killSwitch();
    } else if (data[0] == CONTROL_PROXY_MESSAGE_TYPE_NOTIFICATION_TOKEN) {
        if ((length > NOTI__device_token_min_len) && (length < NOTI__device_token_max_len))
        {
            toxProxyLog(0, "received CONTROL_PROXY_MESSAGE_TYPE_NOTIFICATION_TOKEN message");
            NOTIFICATION__device_token = calloc(1, (length + 1));
            memcpy(NOTIFICATION__device_token, (data + 1), (length - 1));
            toxProxyLog(0, "CONTROL_PROXY_MESSAGE_TYPE_NOTIFICATION_TOKEN: %s", NOTIFICATION__device_token);
            fprintf(stdout, "received token:%s\n", NOTIFICATION__device_token);
            // save notification token to file
            add_token(NOTIFICATION__device_token);
        }
        return;
    } else if (data[0] == CONTROL_PROXY_MESSAGE_TYPE_FRIEND_PUBKEY_FOR_PROXY) {
        if (length != tox_public_key_size() + 1) {
            toxProxyLog(0, "received ControlProxyMessageType_pubKey message with wrong size");
            return;
        }

        const uint8_t *public_key = data + 1;
        tox_friend_add_norequest(tox, public_key, NULL);
        updateToxSavedata(tox);
        char public_key_hex[tox_public_key_hex_size];
        CLEAR(public_key_hex);
        bin2upHex(public_key, tox_public_key_size(), public_key_hex, tox_public_key_hex_size);
        toxProxyLog(0, "added friend of my master (norequest) with pubkey: %s", public_key_hex);
    } else {
        toxProxyLog(0, "received unexpected ControlProxyMessageType");
    }
}

void send_sync_msg_single(Tox *tox, char *pubKeyHex, char *msgFileName)
{
    char *msgPath = calloc(1, strlen(msgsDir) + 1 + strlen(pubKeyHex) + 1 + strlen(msgFileName) + 1);

    // last +1 is for terminating \0 I guess (without it, memory checker explodes..)
    sprintf(msgPath, "%s/%s/%s", msgsDir, pubKeyHex, msgFileName);

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
            toxProxyLog(9, "send_sync_msg_single: wrapped raw message = %p TOX_FILE_KIND_MESSAGEV2_ANSWER", raw_message2);
        } else { // TOX_FILE_KIND_MESSAGEV2_SEND
            tox_messagev2_sync_wrap(fsize, pubKeyBin, TOX_FILE_KIND_MESSAGEV2_SEND,
                                    rawMsgData, 987, 775, raw_message2, msgid2);
            toxProxyLog(9, "send_sync_msg_single: wrapped raw message = %p TOX_FILE_KIND_MESSAGEV2_SEND", raw_message2);
        }

        // save new msgid ----------
        char msgid2_str[tox_public_key_hex_size + 1];
        CLEAR(msgid2_str);
        bin2upHex(msgid2, tox_public_key_size(), msgid2_str, tox_public_key_hex_size);

        char *msgPath_msg_id = calloc(1, 1000);
        if (msgPath_msg_id)
        {
            sprintf(msgPath_msg_id, "%s__%s__", msgPath, msgid2_str);
            toxProxyLog(9, "send_sync_msg_single: writing new msg_id to file: %s", msgPath_msg_id);
            FILE *f_msg_id = fopen(msgPath_msg_id, "wb");
            fwrite(msgid2_str, 1, 1, f_msg_id);
            fclose(f_msg_id);
            free(msgPath_msg_id);
        }
        // save new msgid ----------

        TOX_ERR_FRIEND_SEND_MESSAGE error;
        bool res2 = tox_util_friend_send_sync_message_v2(tox, 0, raw_message2, rawMsgSize2, &error);
        toxProxyLog(9, "send_sync_msg_single: send_sync_msg res=%d; error=%d", (int)res2, error);

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
    //toxProxyLog(3, "sending messages of friend: %s to master", pubKeyHex);

    char *friendDir = calloc(1, strlen(msgsDir) + 1 + strlen(pubKeyHex) +
                             1); // last +1 is for terminating \0 I guess (without it, memory checker explodes..)
    sprintf(friendDir, "%s/%s", msgsDir, pubKeyHex);

    mkdir(msgsDir, S_IRWXU);

    DIR *dfd = opendir(friendDir);

    if (dfd == NULL) {
        // toxProxyLog(1, "Can't open msgsDir for sending messages to master (maybe no single message has been received yet?)");
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
                    toxProxyLog(2, "found message by %s with filename %s", pubKeyHex, dp->d_name);
                    send_sync_msg_single(tox, pubKeyHex, dp->d_name);
                }
            }
        }
    }

    closedir(dfd);
    free(friendDir);
}

void send_sync_msgs(Tox *tox)
{
    mkdir(msgsDir, S_IRWXU);

    // loop over all directories = public-keys of friends we have received messages from
    DIR *dfd = opendir(msgsDir);

    if (dfd == NULL) {
        // toxProxyLog(1, "Can't open msgsDir for sending messages to master (maybe no single message has been received yet?)");
        return;
    }

    struct dirent *dp = NULL;

    while ((dp = readdir(dfd)) != NULL) {
        if (strncmp(dp->d_name, ".", 1) != 0 && strncmp(dp->d_name, "..", 2) != 0) {
            send_sync_msgs_of_friend(tox, dp->d_name);
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
        toxProxyLog(9, "malloc() failed\n");
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
        toxProxyLog(9, "realloc() failed\n");
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
    toxProxyLog(9, "ping_push_service");

    if (NOTIFICATION_METHOD == NOTIFICATION_METHOD_NONE)
    {
        toxProxyLog(9, "ping_push_service:NOTIFICATION_METHOD NONE");
        return 1;
    }

    if (!NOTIFICATION__device_token)
    {
        toxProxyLog(9, "ping_push_service: No NOTIFICATION__device_token");
        return 1;
    }


    if (NOTIFICATION_METHOD == NOTIFICATION_METHOD_TCP)
    {
        toxProxyLog(9, "ping_push_service:NOTIFICATION_METHOD TCP");
        int sockfd = 0;
        int numbytes = 0;
        char buf[PUSH__MAXDATASIZE + 1];
        struct hostent *he = NULL;
        struct sockaddr_in their_addr;

        memset(buf, 0, (PUSH__MAXDATASIZE + 1));

        if ((he = gethostbyname(PUSH__DST_HOST)) == NULL)
        {
            toxProxyLog(9, "ping_push_service:gethostbyname");
            return 1;
        }

        if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
        {
            toxProxyLog(9, "ping_push_service:socket");
            return 1;
        }

        their_addr.sin_family = AF_INET;
        their_addr.sin_port = htons(PUSH__DST_PORT);
        their_addr.sin_addr = *((struct in_addr *)he->h_addr);
        bzero(&(their_addr.sin_zero), 8);

        if (connect(sockfd, (struct sockaddr *)&their_addr, sizeof(struct sockaddr)) == -1)
        {
            toxProxyLog(9, "ping_push_service:connect");
            close(sockfd);
            return 1;
        }

        if (send(sockfd, NOTIFICATION__device_token, strlen(NOTIFICATION__device_token), 0) == -1)
        {
            toxProxyLog(9, "ping_push_service:send");
            close(sockfd);
            return 1;
        }

        if ((numbytes = recv(sockfd, buf, PUSH__MAXDATASIZE, 0)) == -1)
        {
            toxProxyLog(9, "ping_push_service:recv");
            close(sockfd);
            return 1;
        }

        close(sockfd);

        if (numbytes > 2)
        {
            toxProxyLog(9, "ping_push_service:PING sent:result=%c%c %d %d", (char)buf[0], (char)buf[1], (int)buf[0], (int)buf[1]);

            // '79' '75' -> 'OK'
            if (((int)buf[0] == 79) && ((int)buf[1] == 75))
            {
                toxProxyLog(9, "ping_push_service:PING sent:result=OK.");
                return 0;
            }
            else
            {
                toxProxyLog(9, "ping_push_service:PING sent:result=ERR01.");
                return 1;
            }
        }
        else
        {
            toxProxyLog(9, "ping_push_service:PING sent:result=ERR02.");
            return 1;
        }
    }
    else if (NOTIFICATION_METHOD == NOTIFICATION_METHOD_HTTP)
    {
        toxProxyLog(9, "ping_push_service:NOTIFICATION_METHOD HTTP");
        need_send_notification = 1;
        return 1;
    }
    else if (NOTIFICATION_METHOD == NOTIFICATION_METHOD_GOTIFY_UP)
    {
        toxProxyLog(9, "ping_push_service:NOTIFICATION_METHOD GOTIFY_UP");
        need_send_notification = 1;
        return 1;
    }
    else
    {
        return 1;
    }
}

static void *notification_thread_func(void *data)
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
                if (NOTIFICATION_METHOD == NOTIFICATION_METHOD_HTTP)
                {
                    toxProxyLog(9, "ping_push_service:NOTIFICATION_METHOD HTTP");
                    int result = 1;
                    CURL *curl = NULL;
                    CURLcode res = 0;

                    size_t max_buf_len = strlen(HTTP_PUSH__DST_URL) + strlen(NOTIFICATION__device_token) + 1;

                    char buf[max_buf_len + 1];
                    memset(buf, 0, max_buf_len + 1);
                    snprintf(buf, max_buf_len, "%s%s", HTTP_PUSH__DST_URL, NOTIFICATION__device_token);

                    curl = curl_easy_init();

                    if (curl)
                    {
                        struct string s;
                        init_string(&s);

                        curl_easy_setopt(curl, CURLOPT_URL, buf);
                        // toxProxyLog(9, "get_url=%s\n", buf);
                        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writefunc);
                        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &s);

                        res = curl_easy_perform(curl);

                        if (res != CURLE_OK)
                        {
                            toxProxyLog(9, "curl_easy_perform() failed: %s", curl_easy_strerror(res));
                        }
                        else
                        {
                            // toxProxyLog(9, "server_answer=%s\n", s.ptr);

                            char *found = strstr((const char *)s.ptr, (const char *)"OK");

                            if (found == NULL)
                            {
                                toxProxyLog(9, "server_answer=%s\n", s.ptr);
                            }
                            else
                            {
                                toxProxyLog(9, "server_answer:OK:%s\n", s.ptr);
                                result = 0;
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
                else if (NOTIFICATION_METHOD == NOTIFICATION_METHOD_GOTIFY_UP)
                {
                    toxProxyLog(9, "ping_push_service:NOTIFICATION_METHOD GOTIFY_UP");
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

                            toxProxyLog(9, "request=%s\n", buf);

                            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writefunc);
                            curl_easy_setopt(curl, CURLOPT_WRITEDATA, &s);

                            res = curl_easy_perform(curl);

                            if (res != CURLE_OK)
                            {
                                toxProxyLog(9, "curl_easy_perform() failed: %s", curl_easy_strerror(res));
                            }
                            else
                            {
                                long http_code = 0;
                                curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
                                if ((http_code < 300) && (http_code > 199))
                                {
                                    toxProxyLog(9, "server_answer:OK:CURLINFO_RESPONSE_CODE=%ld, %s\n", http_code, s.ptr);
                                    result = 0;
                                }
                                else
                                {
                                    toxProxyLog(9, "server_answer:ERROR:CURLINFO_RESPONSE_CODE=%ld, %s\n", http_code, s.ptr);
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
        usleep_usec(1000 * 400); // sleep 400 ms
    }

    toxProxyLog(2, "Notification:Clean thread exit!\n");
    pthread_exit(0);
}

int main(int argc, char *argv[])
{
    openLogFile();

    mkdir("db", S_IRWXU);

    // ---- test ASAN ----
    // char *x = (char*)malloc(10 * sizeof(char*));
    // free(x);
    // x[0] = 1;
    // ---- test ASAN ----

    fprintf(stdout, "ToxProxy version: %s\n", global_version_string);
    toxProxyLog(2, "ToxProxy version: %s\n", global_version_string);

    read_token_from_file();

    on_start();

#if (NOTIFICATION_METHOD == NOTIFICATION_METHOD_HTTP) || (NOTIFICATION_METHOD == NOTIFICATION_METHOD_GOTIFY_UP)
    curl_global_init(CURL_GLOBAL_ALL);
    need_send_notification = 0;
    notification_thread_stop = 0;

    if (pthread_create(&notification_thread, NULL, notification_thread_func, (void *)NULL) != 0)
    {
        toxProxyLog(0, "Notification Thread create failed\n");
    }
    else
    {
        pthread_setname_np(notification_thread, "t_notif");
        toxProxyLog(2, "Notification Thread successfully created\n");
    }
#endif

    Tox *tox = openTox();

    tox_public_key_hex_size = tox_public_key_size() * 2 + 1;
    tox_address_hex_size = tox_address_size() * 2 + 1;

    const char *name = "ToxProxy";
    tox_self_set_name(tox, (uint8_t *) name, strlen(name), NULL);

    const char *status_message = "Proxy for your messages";
    tox_self_set_status_message(tox, (uint8_t *) status_message, strlen(status_message), NULL);

    bootstrap(tox);

    uint8_t tox_id_bin[tox_address_size()];
    tox_self_get_address(tox, tox_id_bin);
    char tox_id_hex[tox_address_hex_size];
    bin2upHex(tox_id_bin, tox_address_size(), tox_id_hex, tox_address_hex_size);

#ifdef WRITE_MY_TOXID_TO_FILE
    FILE *fp = fopen(my_toxid_filename_txt, "wb");

    if (fp) {
        fprintf(fp, "%s", tox_id_hex);
        fclose(fp);
    }

    FILE *fp2 = fopen(my_toxid_filename_txt2, "wb");

    if (fp2) {
        fprintf(fp2, "%s", tox_id_hex);
        fclose(fp2);
    }
#endif

    size_t friends = tox_self_get_friend_list_size(tox);
    toxProxyLog(9, "ToxProxy startup completed");
    toxProxyLog(9, "My Tox ID = %s", tox_id_hex);
    toxProxyLog(9, "Number of friends = %ld", (long) friends);

    tox_callback_friend_request(tox, friend_request_cb);
    tox_callback_friend_message(tox, friend_message_cb);

#ifdef TOX_HAVE_TOXUTIL
    toxProxyLog(9, "using toxutil");
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
    toxProxyLog(9, "NOT using toxutil");
    tox_callback_self_connection_status(tox, self_connection_status_cb);
    tox_callback_friend_connection_status(tox, friendlist_onConnectionChange);
#endif

    updateToxSavedata(tox);


    long long unsigned int cur_time = time(NULL);
    long long loop_counter = 0;
    int max_tries = 2;

    int try = 0;

    uint8_t off = 1;

    while (1) {
        tox_iterate(tox, NULL);
        usleep_usec(tox_iteration_interval(tox) * 1000);


        if (tox_self_get_connection_status(tox) && off) {
            toxProxyLog(2, "Tox online, took %llu seconds", time(NULL) - cur_time);

            fprintf(stdout, "#############################################################\n");
            fprintf(stdout, "#############################################################\n");
            fprintf(stdout, "\n");
            fprintf(stdout, "ToxID:%s\n", tox_id_hex);
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
            toxProxyLog(2, "Tox NOT online yet, bootstrapping again");
            bootstrap(tox);

            if (try >= max_tries) {
                    toxProxyLog(1, "Tox NOT online for a long time, breaking bootstrap loop and starting iteration anyway.");

                    fprintf(stdout, "#############################################################\n");
                    fprintf(stdout, "#############################################################\n");
                    fprintf(stdout, "\n");
                    fprintf(stdout, "ToxID:%s\n", tox_id_hex);
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

    size_t num_conferences = tox_conference_get_chatlist_size(tox);
    toxProxyLog(2, "num_conferences=%d", (int)num_conferences);

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
                toxProxyLog(2, "Tox NOT online, bootstrapping again\n");
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

#if (NOTIFICATION_METHOD == NOTIFICATION_METHOD_HTTP) || (NOTIFICATION_METHOD == NOTIFICATION_METHOD_GOTIFY_UP)
    notification_thread_stop = 1;
    pthread_join(notification_thread, NULL);

    curl_global_cleanup();
#endif

    if (logfile) {
        fclose(logfile);
        logfile = NULL;
    }

    // HINT: for gprof you need an "exit()" call
    exit(0);
}

