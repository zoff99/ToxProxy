#! /bin/bash


_HOME2_=$(dirname $0)
export _HOME2_
_HOME_=$(cd $_HOME2_;pwd)
export _HOME_


echo $_HOME_
cd $_HOME_
mkdir -p build

export _SRC_=$_HOME_/build/
export _INST_=$_HOME_/inst/

echo $_SRC_
echo $_INST_

mkdir -p $_SRC_
mkdir -p $_INST_

export LD_LIBRARY_PATH=$_INST_/lib/
export PKG_CONFIG_PATH=$_INST_/lib/pkgconfig


if [ 1 ==  2 ]; then

sudo apt-get -y install cmake
sudo apt-get -y install ffmpeg
sudo apt-get -y install libavcodec-dev
sudo apt-get -y install libavdevice-dev
sudo apt-get -y install libexif-dev
sudo apt-get -y install libsodium-dev
sudo apt-get -y install libsqlcipher-dev
sudo apt-get -y install libvpx-dev
sudo apt-get -y install libxv-dev libvdpau-dev libxcb-shm0-dev
sudo apt-get -y install libxv-dev libvdpau-dev libxcb-shm0-dev
sudo apt-get -y install libva-dev
sudo apt-get -y install libopus-dev libvpx-dev
sudo apt-get -y install libopus-dev libx264-dev
sudo apt-get -y install libopus-dev libsodium-dev

sudo apt-get -y install libncursesw5-dev
sudo apt-get -y install libcurl4-gnutls-dev


fi


# build toxcore -------------

if [ "$1""x" != "1x" ]; then

    cd $_SRC_
    rm -Rf ./c-toxcore/
    git clone https://github.com/zoff99/c-toxcore
    cd c-toxcore/
    git checkout "zoff99/zoxcore_local_fork"

    export CFLAGS=" -DMIN_LOGGER_LEVEL=LOGGER_LEVEL_INFO -D_GNU_SOURCE -g -O3 -I$_INST_/include/ -fPIC -Wall -Wextra -Wno-unused-function -Wno-unused-parameter -Wno-unused-variable -Wno-unused-but-set-variable "
    export LDFLAGS=" -O3 -L$_INST_/lib -fPIC "
    ./autogen.sh
    ./configure \
      --prefix=$_INST_ \
      --disable-soname-versions --disable-testing --enable-logging --disable-shared

    make -j $(nproc) || exit 1
    make install

fi

# build toxproxy -------------

cd $_HOME_
cd src/



add_config_flag() { CONFIG_FLAGS="$CONFIG_FLAGS $@";    }
add_c_flag()      { C_FLAGS="$C_FLAGS $@";              }
add_cxx_flag()    { CXX_FLAGS="$CXX_FLAGS $@";          }
add_ld_flag()     { LD_FLAGS="$LD_FLAGS $@";            }
add_flag()        { add_c_flag "$@"; add_cxx_flag "$@"; }

# Our own flags which we can insert in the correct place. We don't use CFLAGS
# and friends here (we unset them below), because they influence config tests
# such as ./configure and cmake tests. Our warning flags break those tests, so
# we can't add them globally here.
CONFIG_FLAGS=""
C_FLAGS=""
CXX_FLAGS=""
LD_FLAGS=""

unset CFLAGS
unset CXXFLAGS
unset CPPFLAGS
unset LDFLAGS

# Optimisation flags.
add_flag -O2 -march=native

# Warn on non-ISO C.
add_c_flag -pedantic
add_c_flag -std=c99

add_flag -g3
add_flag -ftrapv


# Add all warning flags we can.
add_flag -Wall
add_flag -Wextra
add_flag -Weverything

# Disable specific warning flags for both C and C++.

# TODO(iphydf): Clean these up. Probably all of these are actual bugs.
add_flag -Wno-cast-align
# Very verbose, not very useful. This warns about things like int -> uint
# conversions that change sign without a cast and narrowing conversions.
add_flag -Wno-conversion
# TODO(iphydf): Check enum values when received from the user, then assume
# correctness and remove this suppression.
add_flag -Wno-covered-switch-default
# Due to clang's tolower() macro being recursive
# https://github.com/TokTok/c-toxcore/pull/481
add_flag -Wno-disabled-macro-expansion
# We don't put __attribute__ on the public API.
add_flag -Wno-documentation-deprecated-sync
# Bootstrap daemon does this.
add_flag -Wno-format-nonliteral
# struct Foo foo = {0}; is a common idiom.
add_flag -Wno-missing-field-initializers
# Useful sometimes, but we accept padding in structs for clarity.
# Reordering fields to avoid padding will reduce readability.
add_flag -Wno-padded
# This warns on things like _XOPEN_SOURCE, which we currently need (we
# probably won't need these in the future).
add_flag -Wno-reserved-id-macro
# TODO(iphydf): Clean these up. They are likely not bugs, but still
# potential issues and probably confusing.
add_flag -Wno-sign-compare
# Our use of mutexes results in a false positive, see 1bbe446.
add_flag -Wno-thread-safety-analysis
# File transfer code has this.
add_flag -Wno-type-limits
# Callbacks often don't use all their parameters.
add_flag -Wno-unused-parameter
# libvpx uses __attribute__((unused)) for "potentially unused" static
# functions to avoid unused static function warnings.
add_flag -Wno-used-but-marked-unused
# We use variable length arrays a lot.
add_flag -Wno-vla

# Disable specific warning flags for C++.

# Downgrade to warning so we still see it.
# add_flag -Wno-error=documentation-unknown-command
add_flag -Wno-documentation-unknown-command

add_flag -Wno-error=unreachable-code
add_flag -Wno-error=unused-variable


# added by Zoff
# add_flag -Wno-error=double-promotion
add_flag -Wno-double-promotion

# add_flag -Wno-error=missing-variable-declarations
add_flag -Wno-missing-variable-declarations

# add_flag -Wno-error=missing-prototypes
add_flag -Wno-missing-prototypes

add_flag -Wno-error=incompatible-pointer-types-discards-qualifiers
add_flag -Wno-error=deprecated-declarations

# add_flag -Wno-error=unused-macros
add_flag -Wno-unused-macros

#add_flag -Wno-error=bad-function-cast
add_flag -Wno-bad-function-cast

#add_flag -Wno-error=float-equal
add_flag -Wno-float-equal

#add_flag -Wno-error=cast-qual
add_flag -Wno-cast-qual

#add_flag -Wno-error=strict-prototypes
add_flag -Wno-strict-prototypes

#add_flag -Wno-error=gnu-statement-expression
add_flag -Wno-gnu-statement-expression

#add_flag -Wno-error=documentation
add_flag -Wno-documentation

# reactivate this later! ------------
# add_flag -Wno-error=pointer-sign
add_flag -Wno-pointer-sign
# add_flag -Wno-error=extra-semi-stmt
# add_flag -Wno-error=undef
# reactivate this later! ------------


add_flag -Werror
add_flag -fdiagnostics-color=always



export CFLAGS=" -fPIC -std=gnu99 -I$_INST_/include/ -L$_INST_/lib -O3 -g -fstack-protector-all "

clang-10 $CFLAGS \
ToxProxy.c \
$_INST_/lib/libtoxcore.a \
-lopus \
-lvpx \
-lx264 \
-lavcodec \
-lavutil \
-lsodium \
-lm \
-lcurl \
-lpthread \
-o ToxProxy

# -l:libsodium.a \


ls -hal ToxProxy
file ToxProxy
ldd ToxProxy >/dev/null
pwd


