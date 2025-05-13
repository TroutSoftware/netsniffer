redo-ifchange envrc

. ./envrc

mkdir -p $BUILD_DIR/tmp

find plugins -regex ".*\.cc\|.*\.h" > $BUILD_DIR/tmp/format.files

xargs clang-format -i < $BUILD_DIR/tmp/format.files
