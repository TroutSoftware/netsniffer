redo-ifchange envrc deps
. ./envrc

mkdir -p $BUILD_DIR
redo-ifchange test
