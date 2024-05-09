###################################################
#
# (C) 2019 - 2024 Thomas Käfer, Zoff
#
# ToxProxy
#
###################################################

MINGWLIBS=

ismingw = 0
ccmachine = $(shell $(CC) -dumpmachine)
ifeq ($(findstring mingw, $(ccmachine)), mingw)
  ismingw = 1
  CFLAGS += --static
  MINGWLIBS=-liphlpapi
  CFLAGSSQLITE3 += --static
endif

CFLAGS += -g -O3 -fPIC -I./
LIBS = $(shell pkg-config --cflags --libs libsodium libcurl) -pthread
TP_CFLAGS = -Wall -Wextra -std=c99 -pedantic
# -Wno-unused-parameter
LIBSSQLITE3 = -lm
CFLAGSSQLITE3 += -g -O3 -fPIC -I./ -Wall -Wextra -Werror=maybe-uninitialized -std=c99 -pedantic -pthread

ToxProxy: ToxProxy.c toxcore_amalgamation.a sql_tables/gen/csorma.a sqlite3.a
	$(CC) $(CFLAGS) $(TP_CFLAGS) ToxProxy.c toxcore_amalgamation.a sql_tables/gen/csorma.a sqlite3.a $(LIBS) $(MINGWLIBS) -o ToxProxy

sqlite3.a: sqlite3.o
	$(AR) rcs sqlite3.a sqlite3.o

sqlite3.o: csorma/sqlite/sqlite3.c
	$(CC) -c $(CFLAGSSQLITE3) $(LIBSSQLITE3) $< -o $@

sql_tables/gen/csorma.a: sql_tables/*.java
	cd csorma/;javac csorma_generator.java
	cd csorma/;java csorma_generator ../sql_tables/
	cd ./sql_tables/gen/; $(MAKE) csorma.a

toxcore_amalgamation.a: toxcore_amalgamation.o
	ar rcs toxcore_amalgamation.a toxcore_amalgamation.o

toxcore_amalgamation.o: toxcore_amalgamation_no_toxav.c
	$(CC) -c -DTOX_CAPABILITIES_ACTIVE $(CFLAGS) $(LIBS) $< -o $@

clean2:
	rm -f ToxProxy sql_tables/gen/csorma.a sql_tables/gen/Makefile sql_tables/gen/*.* sql_tables/gen/sqlite/*

clean:
	rm -f ToxProxy toxcore_amalgamation.o toxcore_amalgamation.a sql_tables/gen/csorma.a sql_tables/gen/Makefile sql_tables/gen/*.* sql_tables/gen/sqlite/* sqlite3.a sqlite3.o

