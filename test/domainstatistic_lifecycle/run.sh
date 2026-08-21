#!/bin/sh
# Build and run the domainstatistic lifecycle integration test.
# statistic.html is written to $HOME/.dnsforwarder, so HOME is pointed at a
# scratch directory; the template is read from the current working directory.
#
# Usage:
#   sh test/domainstatistic_lifecycle/run.sh
#   CC=clang CFLAGS="-fsanitize=address,undefined" sh test/domainstatistic_lifecycle/run.sh
set -e

Root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
Work=${TMPDIR:-/tmp}/dnsforwarder_ds_lifecycle
Out="$Work/prog"

rm -rf "$Work"
mkdir -p "$Work/home/.dnsforwarder"

# Template with the insertion marker used by the test.
printf '%s' '<html>@@INSERT@@</html>' > "$Work/template.html"

Sources="
$Root/test/domainstatistic_lifecycle/main.c
$Root/domainstatistic.c
$Root/timedtask.c
$Root/linkedqueue.c
$Root/pipes.c
$Root/readconfig.c
$Root/readline.c
$Root/stringchunk.c
$Root/simpleht.c
$Root/stablebuffer.c
$Root/stringlist.c
$Root/array.c
$Root/addresslist.c
$Root/utils.c
$Root/test/stubs.c
"

${CC:-cc} -I"$Root" -g -Wall $CFLAGS -o "$Out" $Sources -lpthread

(cd "$Work" && HOME="$Work/home" timeout 20 "$Out")
