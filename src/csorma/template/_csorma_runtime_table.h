// ==================================================
//    START TABLE: __@@@TABLE@@@__
// ==================================================

typedef struct __@@@TABLE@@@__ __@@@TABLE@@@__;

typedef struct __@@@TABLE@@@__List {
    int64_t items;
    __@@@TABLE@@@__** l;
} __@@@TABLE@@@__List;

struct __@@@TABLE@@@__ {
    // --------- colums --------------------------------
__@@@RT_COLUMNS_STRUCT20@@@__
    // --------- colums --------------------------------

    // --------- functions ------------------------------
    // --------- functions eq ------------------------------
__@@@RT_FUNCS_EQ20@@@__

    // --------- functions set ------------------------------
__@@@RT_FUNCS_SET20@@@__

    // --------- functions B ------------------------------
    int64_t (*count)(__@@@TABLE@@@__ *t);
    __@@@TABLE@@@__List* (*toList)(__@@@TABLE@@@__ *t);
    int64_t (*execute)(__@@@TABLE@@@__ *t);
    // --------- functions ------------------------------

    // --------- meta data ------------------------------
    void *db;
    csorma_s *sql_start;
    csorma_s *sql_set;
    csorma_s *sql_where;
    csorma_s *sql_orderby;
    csorma_s *sql_limit;
    OrmaBindvars *bind_where_vars;
    OrmaBindvars *bind_set_vars;
    // --------- meta data ------------------------------
};
#define orma_new___@@@TABLE@@@__(db) __new___@@@TABLElc@@@__(db)
#define orma_insertInto__@@@TABLE@@@__(t) __insert_into___@@@TABLElc@@@__(t)
#define orma_selectFrom__@@@TABLE@@@__(db) __select_from___@@@TABLElc@@@__(db)
#define orma_update__@@@TABLE@@@__(db) __update___@@@TABLElc@@@__(db)
#define orma_deleteFrom__@@@TABLE@@@__(db) __delete_from___@@@TABLElc@@@__(db)
#define orma_free___@@@TABLE@@@__(t) __free___@@@TABLElc@@@__(t)
#define orma_free___@@@TABLE@@@__List(l) __free___@@@TABLElc@@@___list(l)

__@@@TABLE@@@__ *__new___@@@TABLElc@@@__(void *db);
int64_t __insert_into___@@@TABLElc@@@__(__@@@TABLE@@@__ *t);
__@@@TABLE@@@__ *__update___@@@TABLElc@@@__(void *db);
__@@@TABLE@@@__ *__delete_from___@@@TABLElc@@@__(void *db);
__@@@TABLE@@@__ *__select_from___@@@TABLElc@@@__(void *db);
void __free___@@@TABLElc@@@__(__@@@TABLE@@@__ *t);
void __free___@@@TABLElc@@@___list(__@@@TABLE@@@__List *l);

// ==================================================
//      END TABLE: __@@@TABLE@@@__
// ==================================================

