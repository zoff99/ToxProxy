CC = gcc
CFLAGS += -g -O3 -fPIC -I./
LIBS = $(shell pkg-config --cflags --libs libsodium libcurl) -pthread
TP_CFLAGS = -Wall -Wextra  -std=c99 -pedantic

ToxProxy: ToxProxy.c toxcore_amalgamation.a sql_tables/gen/csorma.a
	$(CC) $(CFLAGS) $(TP_CFLAGS) ToxProxy.c toxcore_amalgamation.a $(LIBS) -o ToxProxy

toxcore_amalgamation.a: toxcore_amalgamation.o
	ar rcs toxcore_amalgamation.a toxcore_amalgamation.o

toxcore_amalgamation.o: toxcore_amalgamation_no_toxav.c
	$(CC) -c $(CFLAGS) $(LIBS) $< -o $@

sql_tables/gen/csorma.a: sql_tables/*.java
	cd csorma/;javac csorma_generator.java
	cd csorma/;java csorma_generator ../sql_tables/
	cd ./sql_tables/gen/; make

clean2:
	rm -f ToxProxy sql_tables/gen/csorma.a sql_tables/gen/Makefile sql_tables/gen/*.* sql_tables/gen/sqlite/*

clean:
	rm -f ToxProxy toxcore_amalgamation.o toxcore_amalgamation.a sql_tables/gen/csorma.a sql_tables/gen/Makefile sql_tables/gen/*.* sql_tables/gen/sqlite/*

