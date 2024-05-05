#!/bin/bash

_HOME2_=$(dirname $0)
export _HOME2_
_HOME_=$(cd $_HOME2_;pwd)
export _HOME_

basedir="$_HOME_""/../"
cd "$basedir"
pwd

gcc "$_HOME_"/randc.c -O3 -o "$_HOME_"/randc

rand_="$_HOME_""/""randc"
projectdir="mycoolstuff"
mkdir -p "$projectdir"/
cd "$projectdir"/

for i in {1..100} ; do

    #{

    tablename=""
    tablename="$tablename"$("$rand_")
    tablefile="_csorma_""$tablename"".java"
    echo "$tablename" : "$tablefile"

    echo "" > "$tablefile"
    echo '@Table' >> "$tablefile"
    echo 'public class '"$tablename" >> "$tablefile"
    echo '{' >> "$tablefile"
    echo '@PrimaryKey(autoincrement = true, auto = true)' >> "$tablefile"
    echo 'public long id;' >> "$tablefile"
    echo '' >> "$tablefile"


    for j in {1..8} ; do
        echo '@Column' >> "$tablefile"

        n=$(($j%4))
        if [ "$n""x" == "0x" ]; then
            echo -n 'public String' >> "$tablefile"
        elif [ "$n""x" == "1x" ]; then
            echo -n 'public int' >> "$tablefile"
        elif [ "$n""x" == "2x" ]; then
            echo -n 'public long' >> "$tablefile"
        else
            echo -n 'public boolean' >> "$tablefile"
        fi

        colname=""
        colname="$colname"$("$rand_")
        echo -n ' '"$colname"' ' >> "$tablefile"

        echo ';' >> "$tablefile"
    done
    echo '}' >> "$tablefile"

    #} &

done

# wait
echo "parallel jobs finished"


cd "$basedir"
echo "generating C code ..."
javac csorma_generator.java  && java csorma_generator ./"$projectdir"/
echo "generating C code DONE"

cd "$basedir"
cd ./"$projectdir"/gen/
make -j 5 asan_csorma_stub && ./csorma_stub



