redo-ifchange ../envrc libml_vars.rc libml_fetch

exec >&2

. ../envrc
. $TMP_FOLDER/libml_vars.rc

rm -rf $LIBML_SRC_DIR
tar -C $BUILD_DIR -xzf $DOWNLOAD_DIR/$LIBDAQ_LOCAL_TAR_GZ_FILE_NAME

redo-ifchange $LIBML_SRC_DIR/configure.sh



