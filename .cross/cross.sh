#!/bin/bash


SODIUM_VERSION="1.0.19"
OPENSSL_VERSION="openssl-3.3.0"
LIBCURL_VERSION="curl-8_7_1"

_HOME2_=$(dirname "$0")
export _HOME2_
_HOME_=$(cd "$_HOME2_" || exit;pwd)
export _HOME_


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
CROSS_COMPILE="" ./Configure --prefix="$_HOME_" no-asm no-shared
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
./configure --host="$CROSS_TRIPLE" \
 --with-openssl="$_HOME_" \
                      --disable-ftp \
                      --disable-file \
                      --disable-ldap \
                      --disable-ldaps \
                      --disable-rtsp \
                      --disable-telnet \
                      --disable-tftp \
                      --disable-pop3 \
                      --disable-imap \
                      --disable-smb \
                      --disable-smtp \
                      --disable-gopher \
                      --disable-mqtt \
                      --disable-manual \
                      --disable-websockets \
                      --with-ca-fallback \
                      --enable-static \
                      --disable-shared


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



