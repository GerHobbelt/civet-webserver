#!/bin/bash
SOURCES="src/internal.h src/util.c src/string.c src/parse_date.c src/options.c src/crypto.c src/auth.c src/unix.c src/mg_printf.c src/http_client.c src/mingoose.c"

for file in  $SOURCES
do
    echo "//-- $file --"
    cat $file
    echo "//-- end of $file --"
done  > src/_all_.c


