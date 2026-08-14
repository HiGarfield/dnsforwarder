#!/bin/sh
# Regression test for WriteFileCallback short-write handling (downloader.c).
#
# Builds main.c together with downloader.c under -DDOWNLOAD_LIBCURL and links
# libcurl, then runs it. The test injects a short-writing stream via
# fopencookie and asserts the callback no longer reports a short write as a
# full success.
set -e

CC="${CC:-cc}"

SAN_FLAGS="-fsanitize=address,undefined"

"$CC" -g -O0 $SAN_FLAGS \
      -DDOWNLOAD_LIBCURL \
      -I../.. \
      main.c \
      stubs.c \
      ../../downloader.c \
      -lcurl -lpthread \
      -o /tmp/downloader_writecb

/tmp/downloader_writecb
echo "rc=$?"
