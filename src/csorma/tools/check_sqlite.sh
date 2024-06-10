#! /bin/bash

_HOME2_=$(dirname $0)
export _HOME2_
_HOME_=$(cd $_HOME2_;pwd)
export _HOME_

basedir="$_HOME_""/../"
cd "$basedir"


r1='https://github.com/sqlite/sqlite'
ver=$(git ls-remote --refs --sort='v:refname' --tags "$r1" \
    | cut --delimiter='/' --fields=3 | grep '^version\-' | tail --lines=1)

echo "$ver"

# 3.45.3 -> 3450300

v1=$(echo "$ver"|sed -e 's#version-##'|awk -F'.' '{print $1}')
v2=$(echo "$ver"|sed -e 's#version-##'|awk -F'.' '{print $2}')
v3=$(echo "$ver"|sed -e 's#version-##'|awk -F'.' '{print $3}')

ver="$v1""$v2""0""$v3""00"
echo "$ver"

sed -i -e 's#_SQLITE_VERSION_=".*"#_SQLITE_VERSION_="'"$ver"'"#' ./tools/download_sqlite_amalgamation.sh

