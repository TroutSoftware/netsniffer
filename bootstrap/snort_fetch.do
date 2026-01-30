redo-ifchange ../envrc version_tags.rc

. ../envrc
. ./version_tags.rc

redo-ifchange snort_vars.rc
. $TMP_FOLDER/snort_vars.rc

exec >&2

[ -d $BUILD_DIR ] || mkdir -p $BUILD_DIR
[ -d $SNORT_SRC_DIR ] && rm -rf $SNORT_SRC_DIR

curl -sL "https://github.com/snort3/snort3/archive/refs/tags/$SNORT_SERVER_FILE_NAME" \
  --output-dir $DOWNLOAD_DIR  --create-dirs -o $SNORT_LOCAL_TAR_GZ_FILE_NAME || \
  (rm $DOWNLOAD_DIR/$SNORT_LOCAL_TAR_GZ_FILE_NAME; exit 1)

redo-ifchange $DOWNLOAD_DIR/$SNORT_LOCAL_TAR_GZ_FILE_NAME
