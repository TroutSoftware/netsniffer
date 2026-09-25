set -e

ROOT_FOLDER="$(cd "$(dirname "$0")" && pwd)"

SOURCE_FOLDER="$ROOT_FOLDER/core/src/trout_plugins"

FIND_CMD="find $SOURCE_FOLDER -type f \( -name '*.cc' -o -name '*.h' \) -print0"

eval "$FIND_CMD" | xargs -0 clang-format -i
