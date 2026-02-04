redo-always  # This should always be rebuild as we rely on ninja to do the actual work

redo-ifchange deps envrc ninja_configure bootstrap/snort_install_debug

. ./envrc

ninja -C $BUILD_DIR/debug >&2
