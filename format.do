set -e

redo-ifchange envrc

. ./envrc

SRC_DIRS="plugins includes"

redo-ifchange $SRC_DIRS

FIND_CMD="find $SRC_DIRS -type f \( -name '*.cc' -o -name '*.h' \) -print0"

eval "$FIND_CMD" | xargs -0 clang-format -i

STAMP=$(eval "$FIND_CMD" | xargs -0 cksum | cksum)

echo $STAMP | redo-stamp
