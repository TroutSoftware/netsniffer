redo-ifchange ../envrc version_tags

. ../envrc
. ./version_tags


exec >snort_fetch.log
exec 2>>snort_fetch.log

[ -d $BUILD_DIR ] || mkdir -p $BUILD_DIR

[ -d $BUILD_DIR/snort3-$snort_tag ] || curl -sL "https://github.com/snort3/snort3/archive/refs/tags/$snort_tag.tar.gz" | tar -C "$BUILD_DIR" -xzf -

# We want this to re-run if $BUILD_DIR is deleted, local changes to the file
# won't be overwritten, as the curl-tar combo is only executed if
# snort3-$snort_tag doesn't exist
redo-ifchange $BUILD_DIR/snort3-$snort_tag/configure_cmake.sh
