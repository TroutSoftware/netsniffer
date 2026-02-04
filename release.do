
redo-always  # This should always be rebuild as we rely on ninja to do the actual work

redo-ifchange deps envrc ninja_configure bootstrap/snort_install

. ./envrc

ninja -C $BUILD_DIR/release >&2
