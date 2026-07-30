set -e


FIND_CMD="find core/src/service_inspectors -type f \( -name '*.cc' -o -name '*.h' \) -print0"

eval "$FIND_CMD" | xargs -0 clang-format -i

