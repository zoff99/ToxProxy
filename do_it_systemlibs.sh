#! /bin/bash


_HOME2_=$(dirname $0)
export _HOME2_
_HOME_=$(cd $_HOME2_;pwd)
export _HOME_


echo $_HOME_

# build toxproxy -------------

cd $_HOME_
cd src/


CFLAGS="-fsanitize=address -fno-omit-frame-pointer -static-libasan" make -j10


ls -hal ToxProxy
file ToxProxy
ldd ToxProxy >/dev/null
pwd


