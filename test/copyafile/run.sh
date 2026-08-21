#!/bin/sh
# Regression test for CopyAFile() short/error write handling (utils.c).
set -e

# The build command below uses ../../ paths that only resolve when this script
# runs from its own directory; `sh test/copyafile/run.sh` from the project
# root used to fail with "fatal error: ../../utils.c: No such file".  cd here
# so the paths work no matter how the test is invoked.
cd "$(dirname "$0")"

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
