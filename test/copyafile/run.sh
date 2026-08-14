#!/bin/sh
# Regression test for CopyAFile() short/error write handling (utils.c).
set -e

CC="${CC:-cc}"

SAN_FLAGS="-fsanitize=address,undefined"

"$CC" -g -O0 $SAN_FLAGS \
      -I../.. \
      main.c \
      stubs.c \
      ../../utils.c \
      ../../addresslist.c \
      ../../stringlist.c \
      ../../stringchunk.c \
      ../../simpleht.c \
      ../../array.c \
      ../../stablebuffer.c \
      -lpthread \
      -o /tmp/copyafile

/tmp/copyafile
echo "rc=$?"
