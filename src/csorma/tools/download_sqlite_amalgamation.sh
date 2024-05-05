#! /bin/bash

amalgamation_url="https://sqlite.org/2024/sqlite-amalgamation-3450300.zip"


_HOME2_=$(dirname $0)
export _HOME2_
_HOME_=$(cd $_HOME2_;pwd)
export _HOME_

basedir="$_HOME_""/../"
cd "$basedir"

wget --continue "$amalgamation_url" -O amalgamation.zip
mkdir "$basedir""/sqlite/"
cd "$basedir""/sqlite/"
unzip -j -o "$basedir""/"amalgamation.zip
cd "$basedir"



