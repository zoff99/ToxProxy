#! /bin/sh
base_url='https://github.com/zoff99/csorma/archive/refs/heads/master.tar.gz'

_HOME2_=$(dirname $0)
export _HOME2_
_HOME_=$(cd $_HOME2_;pwd)
export _HOME_

basedir="$_HOME_""/../"
pkg_file="csorma_src_master.tgz"

cd "$basedir"
wget "$base_url" -O "$pkg_file"
rm -Rf csorma/
tar -xzf "$pkg_file"
rm -f "$pkg_file"
mv csorma-master csorma
