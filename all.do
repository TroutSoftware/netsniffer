redo-ifchange envrc deps
. ./envrc

mkdir -p $BUILD_DIR
redo-ifchange debug
redo-ifchange test