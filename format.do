set -e

redo-ifchange envrc

. ./envrc

redo-ifchange $PD

FIND_CMD="find $PD -type f \( -name '*.cc' -o -name '*.h' \) -print0"

eval "$FIND_CMD" | xargs -0 clang-format -i

STAMP=$(eval "$FIND_CMD" | xargs -0 cksum | cksum)

echo $STAMP | redo-stamp
