# C Simple ORM (Android?)

### Oh nooo, Why?
I was looking around for something very simple and easy to use in pure C and there was nothing around like that.
<br>
It is based on the wonderful Android-Orma by FUJI Goro
<br>
and on my (not so wonderful) sorma<sup>2</sup>
<br>
https://github.com/maskarade/Android-Orma
<br>
https://github.com/gfx
<br>
https://github.com/zoff99/sorma2

<img src="https://raw.githubusercontent.com/zoff99/csorma/refs/heads/master/csorma_coms.png" width="300">


### Features
* pure C
* Thread safe
* safe Strings (UTF-8 or even broken UTF-8 or just random bytes)
* easy to use (for most common SQL operations)
* no dependencies (other than SQLite3 amalagamtion soure file)
* schema update management
* works with ASAN
* works with TSAN
* works with UBSAN
* <b>sqlcipher</b> encryption option (you need to have openssl and libssl and libcrypto installed)

### What is does NOT do
* NOT optimized for speed
* NOT optimized for small memory footprint
* NO complex DB operations like JOIN or UNION etc.
* NO multi column primary keys
* NO non ASCII characters in table and column names
* table and column names MUST NOT start or end with a `_` or a `number`
* table and column names MUST only contain `[a-z][_]` (NO uppercase)
* if table or column name starts with (or contains) `public` or `static` there could be issues<sup>*</sup>

<sup>*</sup><sup><sub><I>try to avoid SQL reserved words in table and column names, there may also be some other naming conflicts.</I></sub></sup>

### Supported architechtures
* Linux
* Raspi
* Windows
* macOS
* macOS silicon arm64
* s390
* mips
* riscV

### Usage
#### Create your first C project with csorma
create a directory for your project:
```bash
mkdir -p ./mysuperstuff/
```

create one file for each database table that you need.
<br>
create file for db table `Person` as `./mysuperstuff/_csorma_Person.java`
<br>(don't worry it is not really Java, we just use the syntax here)
```Java
@Table
public class Person
{
    @PrimaryKey(autoincrement = true)
    public long id;
    @Column
    public String name;
    @Column
    public String address;
    @Column
    public int social_number;
}
```

now create the C sources with the Java CSORMA Generator. <b>you need at least java 17</b>.<br>
```bash
javac csorma_generator.java && java csorma_generator ./mysuperstuff/
```

your project is now ready to start.<br>
enter the project directory:
```bash
cd ./mysuperstuff/gen/
```

now build your C project stub and run it:
```bash
make csorma_stub
./csorma_stub
```

if you want to build your project with <b>sqlcipher</b> (you need to have openssl and libssl and libcrypto installed):
```bash
make clean # clean from the previous build
ENCRYPT_CS=1 make csorma_stub
./csorma_stub
```

the output should look (something) like this:
```
STUB: CSORMA version: 0.99.3-SQLCIPHER
STUB: CSORMA SQLite version: 3.46.1
STUB: CSORMA sqlcipher version: 4.6.1 community
STUB: setting sqlcipher key. result = 0
STUB: disabling WAL mode. result = 0
STUB: schema upgrade from 0 to 1
STUB: creating table: Person
STUB: res1: 0

STUB: all OK

```

you now have your working C project stub.<br>

#### Add some more SQL stuff to your new project

open your C project stub in your favorite C Code Editor or IDE:
```
vim csorma_stub.c
```

now let's add commands<br>
(between the `------- your commands here -------` lines)<br>
to insert a row:
```C
{ // HINT: using blocks here to have `p` be a local var
Person *p = orma_new_Person(o->db);
p->name = csb("Larry Wilson");
p->address = csb("1 Larry Drive, Sunset Town");
p->social_number = 381739;
int64_t inserted_id = orma_insertIntoPerson(p);
orma_free_Person(p);
printf("STUB: inserted id: %lld\n", (long long)inserted_id);
} // HINT: using blocks here to have `p` be a local var
```

now lets count how many Persons have the social number `381739`:
```C
{
Person *p = orma_selectFromPerson(o->db);
printf("STUB: count: %d\n", (int)p->social_numberEq(p, 381739)->count(p));
}
```

now we do the same but use the `less than` operator `Lt()`
```C
{
Person *p = orma_selectFromPerson(o->db);
printf("STUB: count: %d\n", (int)p->social_numberLt(p, 400000)->count(p));
}
```

and insert another Person:
```C
{
Person *p = orma_new_Person(o->db);
p->name = csb("Martha Liebowitz");
p->address = csb("2035 Morning Road, Big City");
p->social_number = 139807;
int64_t inserted_id = orma_insertIntoPerson(p);
orma_free_Person(p);
printf("STUB: inserted id: %lld\n", (long long)inserted_id);
}
```

lets iterate through the result of a select statement:
```C
{
Person *p = orma_selectFromPerson(o->db);
PersonList *pl = p->toList(p);
printf("STUB: pl->items=%lld\n", (long long)pl->items);
Person **pd = pl->l;
for(int i=0;i<pl->items;i++)
{
    printf("STUB: id=%ld\n", (*pd)->id);
    printf("STUB: name=\"%s\"\n", (*pd)->name->s);
    printf("STUB: address=\"%s\"\n", (*pd)->address->s);
    printf("STUB: social_number=\"%d\"\n", (*pd)->social_number);
    pd++;
}
orma_free_PersonList(pl);
}
```

here we update all addresses:
```C
{
Person *p = orma_updatePerson(o->db);
int64_t affected_rows3 = p->addressSet(p, csb("1337 Funky Lane, Lala Land"))->execute(p);
printf("STUB: affected rows: %d\n", (int)affected_rows3);
}
```

if we do the iteration from above again we will see the changed data<br>
it will look something like that:
```
STUB: affected rows: 2
STUB: pl->items=2
STUB: id=1
STUB: name="Larry Wilson"
STUB: address="1337 Funky Lane, Lala Land"
STUB: social_number="381739"
STUB: id=2
STUB: name="Martha Liebowitz"
STUB: address="1337 Funky Lane, Lala Land"
STUB: social_number="139807"
```

delete specifc rows:
```C
{
Person *p = orma_deleteFromPerson(o->db);
int64_t affected_rows2 = p->social_numberEq(p, 139807)->
    nameEq(p, csb("Martha Liebowitz"))->execute(p);
printf("STUB: affected rows: %d\n", (int)affected_rows2);
}
```

in the end run a freehand SQL to drop the table:
```C
{
char *sql3 = "DROP TABLE Person;";
CSORMA_GENERIC_RESULT res3 = OrmaDatabase_run_multi_sql(o, (const uint8_t *)sql3);
printf("STUB: res3: %d\n", res3);
}
```

#### Stub C code, some functions explained

helper function csb and csc:<br>
csb() will build a `csorma_str*` from a `const char*` NULL terminated C string<br>
and csc() will append (or create) a `csorma_str*` from a `buffer and length` (no need for NULL termination)
```C
#define csb(buf)
#define csc(buf,len)
```

include the header file:
```C
#include "csorma_runtime.h"
```

initialize the database:
```C
const char *db_dir = "./";
const char *db_filename = "stub.db";
OrmaDatabase *o = OrmaDatabase_init(
    (uint8_t*)db_dir, strlen(db_dir),
    (uint8_t*)db_filename, strlen(db_filename)
);
```

initialize an encrypted database (if csorma was compiled with encryption support):
```C
const char *db_dir = "./";
const char *db_filename = "stub.db";
OrmaDatabase *o = OrmaDatabase_init(
    (uint8_t*)db_dir, strlen(db_dir),
    (uint8_t*)db_filename, strlen(db_filename)
);

const char *key = "passphrase123!";
int result_setkey = OrmaDatabase_key(o, (uint8_t*)key, strlen(key));
printf("setting sqlcipher key. result = %d\n", result_setkey);

// HINT: set WAL mode
CSORMA_GENERIC_RESULT result_setwal = OrmaDatabase_set_wal_mode(o, true);
printf("enabling WAL mode. result = %d\n", (int)result_setwal);
```

you can also initialize an in-memory database:
```C
const char *db_dir = ":memory:";
const char *db_filename = "";
OrmaDatabase *o = OrmaDatabase_init(
    (uint8_t*)db_dir, strlen(db_dir),
    (uint8_t*)db_filename, strlen(db_filename)
);
```

run a freehand SQL:
```C
char *sql1 = "CREATE TABLE IF NOT EXISTS Message ("
        "message_id	INTEGER NOT NULL,"
        "read	BOOLEAN,"
        "direction	INTEGER ,"
        "text	TEXT,"
        "id	INTEGER,"
        "PRIMARY KEY(\"id\" AUTOINCREMENT)"
        ");"
        "insert into message(message_id,text) values('123','test message');";
CSORMA_GENERIC_RESULT res1 = OrmaDatabase_run_multi_sql(o, sql1);
```

shutdown the database:
```C
OrmaDatabase_shutdown(o);
```

### sqlcipher source code
sqlcipher source code is generated from latest [sqlcipher git repository](https://github.com/sqlcipher/sqlcipher) using this [tool](https://github.com/zoff99/gen_sqlcipher_amalgamation)<br>
you can download the generated sqlcipher code from https://github.com/zoff99/gen_sqlcipher_amalgamation/releases/tag/nightly

### Automated Screenshots taken from CI
<img src="https://github.com/zoff99/csorma/releases/download/nightly/console_01_screen-0.png" width="300">
<br>

<br>
Any use of this project's code by GitHub Copilot, past or present, is done
without our permission.  We do not consent to GitHub's use of this project's
code in Copilot.
<br>
No part of this work may be used or reproduced in any manner for the purpose of training artificial intelligence technologies or systems.


