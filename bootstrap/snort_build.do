redo-always  # This should always be rebuild as we rely on ninja to do the actual work

redo-ifchange ../envrc snort_deps

. ../envrc
. ./version_tags

exec >snort_build.log
exec 2>>snort_build.log

(cd "$BUILD_DIR/snort3-${snort_tag}-build_debug" || exit 1; ninja install)
(cd "$BUILD_DIR/snort3-${snort_tag}-build" || exit 1; ninja install)


