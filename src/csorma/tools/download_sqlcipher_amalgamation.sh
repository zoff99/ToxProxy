#! /bin/bash

base_url="https://github.com/zoff99/gen_sqlcipher_amalgamation/releases/download/nightly/"


_HOME2_=$(dirname $0)
export _HOME2_
_HOME_=$(cd $_HOME2_;pwd)
export _HOME_

basedir="$_HOME_""/../"
cd "$basedir"

mkdir "$basedir""/sqlcipher/"
cd "$basedir""/sqlcipher/"
wget "$base_url""sqlite3.c" -O sqlite3.c
wget "$base_url""sqlite3.h" -O sqlite3.h
wget "$base_url""sqlite3ext.h" -O sqlite3ext.h
cd "$basedir"

