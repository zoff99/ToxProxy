#!/bin/sh


SODIUM_VERSION="1.0.19"
OPENSSL_VERSION="openssl-3.3.0"
LIBCURL_VERSION="curl-8_7_1"

# ------- libsodium -------
pushd .
git clone https://github.com/jedisct1/libsodium
cd libsodium/
git checkout "$SODIUM_VERSION"
./autogen.sh
./configure --host="$CROSS_TRIPLE" --disable-shared --enable-static --with-pic
make -j10
make install
popd
# ------- libsodium -------

# ------- openssl -------
pushd .
git clone https://github.com/openssl/openssl
cd openssl/
git checkout "$OPENSSL_VERSION"
CROSS_COMPILE="" ./Configure no-asm no-shared
sed -i -e 's#-m64##g' Makefile
make -j10
make install
popd
# ------- openssl -------

# ------- libcurl -------
pushd .
git clone https://github.com/curl/curl
cd curl/
git checkout "$LIBCURL_VERSION"
autoreconf -fi
./configure --host="$CROSS_TRIPLE" --disable-shared --enable-static --with-pic --with-openssl
make -j10
make install
popd
# ------- libcurl -------

cd src/
cd ./sql_tables/gen/
make csorma.a
cd ../../
make toxcore_amalgamation.a
make sqlite3.a

make ToxProxy



