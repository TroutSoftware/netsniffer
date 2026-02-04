redo-always  # This should always be rebuild as we rely on ninja to do the actual work

redo-ifchange ../envrc snort_config version_tags.rc

. ../envrc
. ./version_tags.rc

exec >&2

(cd "$BUILD_DIR/snort3-${snort_tag}-build_debug" || exit 1; ninja install)
