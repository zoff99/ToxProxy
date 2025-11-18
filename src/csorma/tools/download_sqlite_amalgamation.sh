#! /bin/bash

_SQLITE_VERSION_="3510000"

amalgamation_url="https://sqlite.org/2025/sqlite-amalgamation-""$_SQLITE_VERSION_"".zip"


_HOME2_=$(dirname $0)
export _HOME2_
_HOME_=$(cd $_HOME2_;pwd)
export _HOME_

basedir="$_HOME_""/../"
cd "$basedir"

rm -f amalgamation.zip
wget "$amalgamation_url" -O amalgamation.zip
mkdir "$basedir""/sqlite/"
cd "$basedir""/sqlite/"
unzip -j -o "$basedir""/"amalgamation.zip
cd "$basedir"



