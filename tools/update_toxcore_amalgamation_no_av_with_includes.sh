#! /bin/sh
url='https://raw.githubusercontent.com/zoff99/c-toxcore/refs/heads/zoff99/zoxcore_local_fork/amalgamation/toxcore_amalgamation_no_toxav.c'
url2='https://raw.githubusercontent.com/zoff99/c-toxcore/refs/heads/zoff99/zoxcore_local_fork/toxcore/tox.h'
url3='https://raw.githubusercontent.com/zoff99/c-toxcore/refs/heads/zoff99/zoxcore_local_fork/toxutil/toxutil.h'
url4='https://raw.githubusercontent.com/zoff99/c-toxcore/refs/heads/zoff99/zoxcore_local_fork/ngc_ppeerlist/mid_roster.h'

_HOME2_=$(dirname $0)
export _HOME2_
_HOME_=$(cd $_HOME2_;pwd)
export _HOME_

basedir="$_HOME_""/../"

cd "$basedir"
cd src/
wget "$url" --no-cache -O toxcore_amalgamation_no_toxav.c
cd tox/
wget "$url2" --no-cache -O tox.h
wget "$url3" --no-cache -O toxutil.h
wget "$url4" --no-cache -O mid_roster.h
