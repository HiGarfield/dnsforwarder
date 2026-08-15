#!/bin/sh
# Regression tests for bug-fix round 2.
#
# Covers:
#   Bug #1  : dnscache.c expired-marker byte write triggered -Woverflow
#             (writing 0xFD into a signed char field). Fixed by casting the
#             destination through `unsigned char` so the stored byte is exactly
#             0xFD and the strict build is warning-free.
#   Bug #4-#11: C89 / ISO C90 source & header incompatibilities
#             (trailing enum commas, non-`int` bit-field members, GNU `//`
#             comments, GNU anonymous variadic macros). Fixed so the whole
#             codebase compiles cleanly under -std=c89 -pedantic-errors.
#
# No ASan/UBSan runtime is available on this MinGW toolchain, so we prove the
# fixes with the compiler itself: the strict C89 build must pass with zero
# errors and the -Woverflow promotion must not fire.
set -e
cd "$(dirname "$0")/../.."

CC="${CC:-gcc}"
FAIL=0

echo "=== Bug #1: dnscache.c 0xFD marker write must not overflow (-Werror=overflow) ==="
if $CC -std=c89 -pedantic -Wall -Wextra -Werror=overflow -fsyntax-only -I. dnscache.c 2>err.log
then
    echo "PASS: dnscache.c compiles without -Woverflow"
else
    echo "FAIL: dnscache.c still triggers -Woverflow"
    cat err.log
    FAIL=1
fi
rm -f err.log

echo
echo "=== Bug #2/#3: timedtask.c (POSIX-lock exit guard) compiles clean under strict C89 ==="
if $CC -std=c89 -pedantic-errors -Werror -Werror=overflow -Werror=uninitialized -Werror=maybe-uninitialized -fsyntax-only -I. timedtask.c 2>err3.log
then
    echo "PASS: timedtask.c compiles clean"
else
    echo "FAIL: timedtask.c has a semantic warning/error"
    cat err3.log
    FAIL=1
fi
rm -f err3.log

echo
echo "=== Bugs #4-#11: every core .c compiles under strict ISO C90 (-pedantic-errors) ==="
CORE="array.c bst.c cacheht.c cachettlcrtl.c dnscache.c dnsgenerator.c dnsparser.c \
      dnsrelated.c downloader.c dynamichosts.c filter.c goodiplist.c hosts.c \
      hostscontainer.c hostsutils.c iheader.c ipchunk.c ipmisc.c linkedqueue.c \
      logs.c main.c mcontext.c mmgr.c pipes.c ptimer.c readconfig.c readline.c \
      simpleht.c socketpool.c socketpuller.c stablebuffer.c stringchunk.c \
      stringlist.c tcpfrontend.c tcpm.c timedtask.c udpfrontend.c udpm.c \
      utils.c winmsgque.c domainstatistic.c statichosts.c"

for f in $CORE
do
    if $CC -std=c89 -pedantic-errors -Werror -fsyntax-only -I. "$f" 2>err2.log
    then
        :
    else
        echo "FAIL: $f does not compile under strict C89"
        cat err2.log
        FAIL=1
    fi
done
rm -f err2.log

if [ "$FAIL" -eq 0 ]
then
    echo
    echo "ALL ROUND-2 REGRESSION TESTS PASSED"
    exit 0
else
    echo
    echo "SOME ROUND-2 REGRESSION TESTS FAILED"
    exit 1
fi
