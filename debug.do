redo-always  # This should always be rebuild as we rely on ninja to do the actuall work

redo-ifchange deps envrc ninja_configure

. ./envrc

ninja -C $BUILD_DIR/debug >&2
