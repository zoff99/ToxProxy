CC = gcc
CFLAGS = -g -O3 -fPIC -I./
LIBS = $(shell pkg-config --cflags --libs libsodium libcurl) -pthread

ToxProxy: ToxProxy.c
	$(CC) $(CFLAGS) ToxProxy.c $(LIBS) -o ToxProxy

clean:
	rm -f ToxProxy

