redo-ifchange ../envrc libdaq_vars.rc libdaq_fetch

exec >&2

. ../envrc
. $TMP_FOLDER/libdaq_vars.rc

rm -rf $LIBDAQ_SRC_DIR
tar -C $BUILD_DIR -xzf $DOWNLOAD_DIR/$LIBDAQ_LOCAL_TAR_GZ_FILE_NAME

redo-ifchange $LIBDAQ_SRC_DIR/bootstrap
