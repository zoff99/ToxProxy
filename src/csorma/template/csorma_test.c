#include "csorma_runtime.h"
#include "pthread.h"
#ifdef __linux__
#include <stdatomic.h>
#endif
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

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

pthread_t thr_1;
pthread_t thr_2;
#ifdef __linux__
_Atomic int thr_1_stop = 0;
_Atomic int thr_2_stop = 0;
#else
int thr_1_stop = 0;
int thr_2_stop = 0;
#endif
OrmaDatabase *o = NULL;
char *utf8_test_file_broken1 = "invalid_UTF-8-test.dat";
char *utf8_test_file2 = "UTF-8-demo.html";
uint64_t counter1 = 0;
uint64_t counter2 = 0;

struct file_content {
    long bytes;
    char *buf;
};

struct file_content fc;

// gives a counter value that increaes every millisecond
static uint64_t csorma_current_time_monotonic_default()
{
    uint64_t time = 0;
    struct timespec clock_mono;
    clock_gettime(CLOCK_MONOTONIC, &clock_mono);
    time = 1000ULL * clock_mono.tv_sec + (clock_mono.tv_nsec / 1000000ULL);
    return time;
}

static void usleep_usec(uint64_t usec)
{
    struct timespec ts;
    ts.tv_sec = usec / 1000000;
    ts.tv_nsec = (usec % 1000000) * 1000;
    nanosleep(&ts, NULL);
}

static void yieldcpu(uint32_t ms)
{
    usleep_usec(1000 * ms);
}

static void read_file_to_buf1()
{
    if (fc.buf != NULL) { free(fc.buf); }
    FILE *f = fopen(utf8_test_file_broken1, "rb");
    fseek(f, 0L, SEEK_END);
    long numbytes = ftell(f);
    fseek(f, 0L, SEEK_SET);
    char *buf = (char*)calloc(numbytes, sizeof(char));
    size_t UNUSED(fr1) = fread(buf, sizeof(char), numbytes, f);
    fclose(f);
    fc.bytes = numbytes;
    fc.buf = buf;
}

static void read_file_to_buf2()
{
    if (fc.buf != NULL) { free(fc.buf); }
    FILE *f = fopen(utf8_test_file2, "rb");
    fseek(f, 0L, SEEK_END);
    long numbytes = ftell(f);
    fseek(f, 0L, SEEK_SET);
    char *buf = (char*)calloc(numbytes, sizeof(char));
    size_t UNUSED(fr1) = fread(buf, sizeof(char), numbytes, f);
    fclose(f);
    fc.bytes = numbytes;
    fc.buf = buf;
}

void *thr_1_func(void * UNUSED(data))
{
    while (thr_1_stop == 0) {
        // ----------- insert SQL -----------
        csorma_s *str1 = NULL;
        csorma_s *str2 = NULL;
        str1 = csb("AAAAAAA_x");
        // str2 = csc("thread_1________TEXT11________", strlen("thread_1________TEXT11________"));
        // str2 = csorma_str_con(str2, "thread_1_x", strlen("thread_1_x"));
        Message *m = orma_new_Message(o->db);
        // printf("TEST: THR1: new message handle: %p\n", m);
        m->tox_friendpubkey = str1;
        m->text = str2;
        int64_t rowid = orma_insertIntoMessage(m);
        printf("TEST: THR1: rowid: %ld\n", rowid);
        counter1++;
        orma_free_Message(m);
        // ----------- insert SQL -----------
        // yieldcpu(1);
    }
    printf("TEST: THR1: Thread 1 finished\n");
    pthread_exit(0);
}

void *thr_2_func(void * UNUSED(data))
{
    while (thr_2_stop == 0) {
        // ----------- insert SQL -----------
        csorma_s *str1 = NULL;
        str1 = csb("AAAAAAA_x");
        Message *m = orma_new_Message(o->db);
        // printf("TEST: THR2: new message handle: %p\n", m);
        m->tox_friendpubkey = str1;
        csorma_s *str3 = csb("");
        m->text = str3;
        int64_t rowid = orma_insertIntoMessage(m);
        printf("TEST: THR2: rowid: %ld\n", rowid);
        counter2++;
        orma_free_Message(m);
        // ----------- insert SQL -----------
        // yieldcpu(1);
    }
    printf("TEST: THR2: Thread 2 finished\n");
    pthread_exit(0);
}

int main()
{
    printf("TEST: CSORMA version: %s\n", csorma_get_version());
    printf("TEST: CSORMA SQLite version: %s\n", csorma_get_sqlite_version());
    printf("TEST: CSORMA sqlcipher version: %s\n", csorma_get_sqlcipher_version());

    // ----------- initialize DB -----------
#ifdef _TEST_INMEMORY_DB_
    const char *db_dir = ":memory:";
    const char *db_filename = "";
#else // test with regular db file
    const char *db_dir = "./";
    const char *db_filename = "test.db";
#endif
    o = OrmaDatabase_init((uint8_t*)db_dir,
            strlen(db_dir),
            (uint8_t*)db_filename, strlen(db_filename));
    printf("TEST: database handle: %p\n", (void *)o);
    // ----------- initialize DB -----------

#ifdef ENCRYPT_CSORMA
    printf("TEST: csorma was compiled with sqlcipher encryption\n");
#endif

    const char *key = "passphrase123!";
    int r = OrmaDatabase_key(o, (uint8_t*)key, strlen(key));
    printf("TEST: setting sqlcipher key. result = %d\n", r);

    {
        CSORMA_GENERIC_RESULT res1 = OrmaDatabase_set_wal_mode(o, true);
        printf("TEST: activating WAL mode. result = %d\n", (int)res1);
    }

    // ----------- freehand SQL -----------
    char *sql1 = "CREATE TABLE IF NOT EXISTS \"Message\" ("
  "\"id\" INTEGER,"
  "\"message_id\" INTEGER,"
  "\"tox_friendpubkey\" TEXT,"
  "\"direction\" INTEGER,"
  "\"tox_message_type\" INTEGER,"
  "\"trifa_message_type\" INTEGER,"
  "\"state\" INTEGER,"
  "\"ft_accepted\" BOOLEAN,"
  "\"ft_outgoing_started\" BOOLEAN,"
  "\"filedb_id\" INTEGER,"
  "\"filetransfer_id\" INTEGER,"
  "\"sent_timestamp\" INTEGER,"
  "\"sent_timestamp_ms\" INTEGER,"
  "\"rcvd_timestamp\" INTEGER,"
  "\"rcvd_timestamp_ms\" INTEGER,"
  "\"read\" BOOLEAN,"
  "\"send_retries\" INTEGER,"
  "\"is_new\" BOOLEAN,"
  "\"text\" TEXT,"
  "\"filename_fullpath\" TEXT,"
  "\"msg_id_hash\" TEXT,"
  "\"raw_msgv2_bytes\" TEXT,"
  "\"msg_version\" INTEGER,"
  "\"resend_count\" INTEGER,"
  "\"ft_outgoing_queued\" BOOLEAN,"
  "\"msg_at_relay\" BOOLEAN,"
  "\"msg_idv3_hash\" TEXT,"
  "\"sent_push\" INTEGER,"
  "\"filetransfer_kind\" INTEGER,"
  "PRIMARY KEY(\"id\" )"
");"
        "insert into message(message_id,tox_friendpubkey) values('111', '00f03428wierwrwer09wi9qie');"
        "insert into message(message_id,tox_friendpubkey) values('344', '11f03428wierwrwer09wi9qie');"
        "insert into message(message_id,tox_friendpubkey) values('344', '33f03428wierwrwer09wi9qie');"
        ;
    CSORMA_GENERIC_RESULT res1 = OrmaDatabase_run_multi_sql(o, (const uint8_t *)sql1);
    printf("TEST: res1: %d\n", res1);
    // ----------- freehand SQL -----------

    // ----------- freehand SQL -----------
    char *sql2 = "SELECT count(*) from Message;";
    CSORMA_GENERIC_RESULT res2 = OrmaDatabase_run_multi_sql(o, (const uint8_t *)sql2);
    printf("TEST: res2: %d\n", res2);
    // ----------- freehand SQL -----------

    // ----------- insert SQL -----------
    csorma_s *str1 = NULL;
    csorma_s *str2 = NULL;
    str1 = csb("AAAAAAA");
    // str2 = csc("________TEXT11________", strlen("________TEXT11________"));
    // str2 = csorma_str_con(str2, "1234", 4);
    Message *m = orma_new_Message(o->db);
    printf("TEST: new message handle: %p\n", (void *)m);
    m->tox_friendpubkey = str1;

    uint8_t *c = calloc(1, 5);
    uint8_t *c_p = c;
    *c_p = '\xF0';
    c_p++;
    *c_p = '\x80';
    c_p++;
    *c_p = '\x80';
    c_p++;
    *c_p = '\x80';
    c_p++;
    str2 = csorma_str_con(str2, (const char *)c, 4);
    free(c);

    m->text = str2;
    m->message_id = 344;

    int64_t rowid = orma_insertIntoMessage(m);
    printf("TEST: rowid: %ld\n", rowid);
    orma_free_Message(m);
    // ----------- insert SQL -----------

    // ----------- insert SQL -----------
    read_file_to_buf1();
    csorma_s *str10 = csc(fc.buf, fc.bytes);
    Message *m10 = orma_new_Message(o->db);
    m10->text = str10;
    m10->message_id = 344;

    int64_t rowid10 = orma_insertIntoMessage(m10);
    printf("TEST: rowid 10: %ld\n", rowid10);
    orma_free_Message(m10);
    // ----------- insert SQL -----------

    // ----------- insert SQL -----------
    read_file_to_buf2();
    csorma_s *str11 = csc(fc.buf, fc.bytes);
    Message *m11 = orma_new_Message(o->db);
    m11->text = str11;
    m11->message_id = 344;

    int64_t rowid11 = orma_insertIntoMessage(m11);
    printf("TEST: rowid 11: %ld\n", rowid11);
    orma_free_Message(m11);
    // ----------- insert SQL -----------

    // ----------- count(*) SQL -----------
    Message *m2 = orma_selectFromMessage(o->db);
    printf("count m2: %d\n", (int)(m2->count(m2)));
    // ----------- count(*) SQL -----------

    // ----------- count(*) SQL -----------
    Message *m3 = orma_selectFromMessage(o->db);
    printf("TEST: new message handle: %p\n", (void *)m3);
    printf("count m3: %d\n", (int)m3->message_idEq(m3, 3)->message_idEq(m3, 3)->count(m3));
    // ----------- count(*) SQL -----------

    // ----------- count(*) SQL -----------
    Message *m4 = orma_selectFromMessage(o->db);
    printf("TEST: new message handle: %p\n", (void *)m4);
    printf("count m4: %d\n", (int)m4->message_idEq(m4, 344)->count(m4));
    // ----------- count(*) SQL -----------

    // ----------- empty csorma_s string -----------
    csorma_s *xx = csb("");
    printf("TEST: xx null_terminator: %d\n", xx->n);
    printf("TEST: xx len: %d\n", xx->l);
    printf("TEST: xx s_ptr: %p\n", xx->s);
    printf("TEST: xx str=\"%s\"\n", xx->s);
    csorma_str_free(xx);
    // ----------- empty csorma_s string -----------

#if 1
    thr_1_stop = 0;
    if (pthread_create(&thr_1, NULL, thr_1_func, (void *)NULL) != 0)
    {
        printf("TEST: Thread 1 create failed\n");
    }
    else
    {
        printf("TEST: Thread 1 successfully created\n");
    }

    thr_2_stop = 0;
    if (pthread_create(&thr_2, NULL, thr_2_func, (void *)NULL) != 0)
    {
        printf("TEST: Thread 2 create failed\n");
    }
    else
    {
        printf("TEST: Thread 2 successfully created\n");
    }

    uint64_t ts1 = csorma_current_time_monotonic_default();

    // HINT: let the threads run for a few seconds
    yieldcpu(2 * 1000);
    thr_1_stop = 1;
    pthread_join(thr_1, NULL);
    thr_2_stop = 1;
    pthread_join(thr_2, NULL);

    uint64_t ts2 = csorma_current_time_monotonic_default();
    float delta_t = ((ts2 - ts1) / 1000);
    if (delta_t > 0)
    {
        printf("inserts/sec = %0.2f\n", (double)((double)(counter1 + counter2) / (double)delta_t));
    }
#endif

    // ----------- slect test -----------
    printf("TEST: SELECT TEST *****************************\n");
    Message *m5 = orma_selectFromMessage(o->db);
    printf("TEST: new message handle: %p\n", (void *)m5);
    MessageList *ml = m5->message_idEq(m5, 344)->orderByidDesc(m5)->toList(m5);
    // MessageList *ml = m5->toList(m5);
    printf("count m5: %p\n", (void *)ml);
    printf("TEST: ml->items=%ld\n", ml->items);
    Message **md = ml->l;
    for(int i=0;i<ml->items;i++)
    {
        printf("TEST: id=%ld\n", (*md)->id);
        printf("TEST: mid=%ld\n", (*md)->message_id);
        printf("TEST: pk=\"%s\"\n", (*md)->tox_friendpubkey->s);
        // printf("TEST: text=\"%s\"\n", (*md)->text->s);
        // printf("TEST: text len=%d\n", (*md)->text->l);
        if ((*md)->text->l == 13737)
        {
            printf("TEST: text len=%d\n", (*md)->text->l);
            // printf("TEST: text content=%s\n", (*md)->text->s);
        }
        else if ((*md)->text->l >= 3000)
        {
            printf("TEST: text len=%d\n", (*md)->text->l);
        }
        md++;
    }
    orma_free_MessageList(ml);
    // ----------- slect test -----------

    // ----------- freehand SQL -----------
    char *sql3 = "DROP TABLE Message;";
    CSORMA_GENERIC_RESULT res3 = OrmaDatabase_run_multi_sql(o, (const uint8_t *)sql3);
    printf("TEST: res3: %d\n", res3);
    // ----------- freehand SQL -----------

    // ----------- shutdown DB -----------
    OrmaDatabase_shutdown(o);
    // ----------- shutdown DB -----------

    free(fc.buf);

    printf("\n");
    printf("TEST: all OK\n");
    printf("\n");

    return 0;
}

#ifdef __cplusplus
}  // extern "C"
#endif
