redo-always  # This should always be rebuild as we rely on ninja to do the actuall work

redo-ifchange envrc debug_config

. ./envrc

ninja -C $BUILD_DIR/debug >&2
