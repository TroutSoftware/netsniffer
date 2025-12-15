redo-ifchange ../envrc libml_vars.rc

exec >&2

. ../envrc
. $TMP_FOLDER/libml_vars.rc

curl -sL https://github.com/snort3/libml/archive/refs/tags/$LIBML_SERVER_FILE_NAME \
  --output-dir $DOWNLOAD_DIR  --create-dirs -o $LIBDAQ_LOCAL_TAR_GZ_FILE_NAME || \
  (rm $DOWNLOAD_DIR/$LIBML_TAR_GZ_FILE_NAME; exit 1)

redo-ifchange $DOWNLOAD_DIR/$LIBML_TAR_GZ_FILE_NAME
