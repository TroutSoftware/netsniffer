
redo-ifchange ../envrc snort_fetch

. ../envrc
. ./version_tags.rc

redo-ifchange snort_vars.rc
. $TMP_FOLDER/snort_vars.rc


# todo: Temp download, move to snort_fetch when done...
#curl -sL "https://github.com/snort3/snort3/archive/refs/tags/$SNORT_SERVER_FILE_NAME" \
#  --output-dir $DOWNLOAD_DIR  --create-dirs -o $SNORT_LOCAL_TAR_GZ_FILE_NAME || \
#  (rm $DOWNLOAD_DIR/$SNORT_LOCAL_TAR_GZ_FILE_NAME; exit 1)


# unpack temporary copy
SNORT_UNMODIFIED_FOLDER=$TMP_FOLDER/snort3-$snort_tag

rm -rf $SNORT_UNMODIFIED_FOLDER
tar -C $TMP_FOLDER -xzf $DOWNLOAD_DIR/$SNORT_LOCAL_TAR_GZ_FILE_NAME

#trap 'rm -rf "$SNORT_UNMODIFIED_FOLDER"' EXIT

PATCH_NAME="$PWD/snort.patch"

diff -urN "$SNORT_UNMODIFIED_FOLDER" "$SNORT_SRC_DIR" | \
  sed "s|$SNORT_UNMODIFIED_FOLDER|a|g; s|$SNORT_SRC_DIR|b|g" > $PATCH_NAME || true


