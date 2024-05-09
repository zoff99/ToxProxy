#!/bin/bash

_HOME2_=$(dirname $0)
export _HOME2_
_HOME_=$(cd $_HOME2_;pwd)
export _HOME_

basedir="$_HOME_""/../"
cd "$basedir"
pwd

projectdir="mycoolstuff"
mkdir -p "$projectdir"/
cd "$projectdir"/


# table ----------
    tablename="group"
    tablefile="_csorma_""$tablename"".java"
    echo "$tablename" : "$tablefile"

    echo "" > "$tablefile"
    echo '@Table' >> "$tablefile"
    echo 'public class '"$tablename" >> "$tablefile"
    echo '{' >> "$tablefile"
    echo '@PrimaryKey(autoincrement = true, auto = true)' >> "$tablefile"
    echo 'public long id;' >> "$tablefile"
    echo '' >> "$tablefile"


    j=1
    # column ----------
        j=$[ j + 1 ]
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

        colname="like"
        echo -n ' '"$colname"' ' >> "$tablefile"

        echo ';' >> "$tablefile"
    # column ----------


echo '}' >> "$tablefile"

cd "$basedir"
echo "generating C code ..."
javac csorma_generator.java  && java csorma_generator ./"$projectdir"/
echo "generating C code DONE"

cd "$basedir"
cd ./"$projectdir"/gen/
make -j 5 asan_csorma_stub && ./csorma_stub



