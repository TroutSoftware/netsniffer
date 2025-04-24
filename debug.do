redo-ifchange envrc debug_config

. ./envrc

ninja -C $BUILD_DIR/debug >&2
