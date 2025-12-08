redo-ifchange ../envrc version_tags libml_fetch libml_vars

exec >&2

. ../envrc
. ./version_tags
. $TMP_FOLDER/libml_vars

rm -rf $LIBML_SRC_DIR
tar -C $BUILD_DIR -xzf $DOWNLOAD_DIR/$LIBML_TAR_GZ_FILE_NAME

redo-ifchange $LIBML_SRC_DIR/configure.sh



