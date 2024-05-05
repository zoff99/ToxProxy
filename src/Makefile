CC = gcc
CFLAGS += -g -O3 -fPIC -I./
LIBS = $(shell pkg-config --cflags --libs libsodium libcurl) -pthread
TP_CFLAGS = -Wall

ToxProxy: ToxProxy.c toxcore_amalgamation.a
	$(CC) $(CFLAGS) $(TP_CFLAGS) ToxProxy.c toxcore_amalgamation.a $(LIBS) -o ToxProxy

toxcore_amalgamation.a: toxcore_amalgamation.o
	ar rcs toxcore_amalgamation.a toxcore_amalgamation.o

toxcore_amalgamation.o: toxcore_amalgamation_no_toxav.c
	$(CC) -c $(CFLAGS) $(LIBS) $< -o $@

clean:
	rm -f ToxProxy toxcore_amalgamation.o toxcore_amalgamation.a

