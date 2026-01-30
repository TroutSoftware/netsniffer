
exec >&2

redo-ifchange ../envrc  snort_fetch

. ../envrc
. ./version_tags.rc

redo-ifchange $TMP_FOLDER/snort_vars.rc
. $TMP_FOLDER/snort_vars.rc

[ -d $BUILD_DIR ] || mkdir -p $BUILD_DIR
[ -d $SNORT_SRC_DIR ] && rm -rf $SNORT_SRC_DIR

tar -C "$BUILD_DIR" -xzf $DOWNLOAD_DIR/$SNORT_LOCAL_TAR_GZ_FILE_NAME

# TODO: This is not safe if someone manually change configure_cmake.sh as it will imidialty wipe that change
redo-ifchange $BUILD_DIR/snort3-$snort_tag/configure_cmake.sh

# Apply patch if it exisits, otherwise do if it is checked out later
# TODO: This is not safe for local modifications, think about tripwire protection
if [ -f snort.patch ]; then
    redo-ifchange snort.patch
    patch -d "$SNORT_SRC_DIR" -p1 < snort.patch
else
    redo-ifcreate snort.patch
fi
