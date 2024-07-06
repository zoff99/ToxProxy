#! /bin/sh
url='https://github.com/zoff99/csorma/archive/refs/heads/master.tar.gz'

_HOME2_=$(dirname $0)
export _HOME2_
_HOME_=$(cd $_HOME2_;pwd)
export _HOME_

basedir="$_HOME_""/../"

cd "$basedir"
cd src/
rm -Rf csorma/
wget "$url" -O master.tar.gz
mkdir -p csorma/
tar -xzvf master.tar.gz --strip-components=1 -C ./csorma/
rm -f master.tar.gz
