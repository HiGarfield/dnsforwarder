#! /bin/sh
# Regression test: the tree must compile under `-std=c89 -pedantic-errors`
# (hard project constraint).  This guards the C99-identifier shims in common.h
# (snprintf/vsnprintf/va_copy) and the non-constant aggregate-initializer fix
# in utils.c.
set -e

DIR=$(cd "$(dirname "$0")" && pwd)
cd "$DIR/../.."

CC=${CC:-cc}
STRICT="-std=c89 -pedantic-errors -Wall -Wextra -D_POSIX_C_SOURCE=200809L -D_DEFAULT_SOURCE -I."

# (1) Compile the real translation units that exercise the previously-hidden
#     identifiers under the strict flags.  Any failure here means a regression.
for f in dnsparser.c logs.c utils.c iheader.c dnsgenerator.c dnsrelated.c; do
    $CC $STRICT -c "$f" -o "/tmp/_c89_shim_$(basename "$f").o"
done

# (2) Runtime proof that the shims actually link and behave (compile + run).
$CC $STRICT "test/c89_shim/main.c" -o "/tmp/_c89_shim_bin"
"/tmp/_c89_shim_bin"
