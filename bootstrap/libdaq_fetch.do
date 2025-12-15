redo-ifchange ../envrc libdaq_vars.rc

exec >&2

. ../envrc
. $TMP_FOLDER/libdaq_vars.rc

curl -sL https://github.com/snort3/libdaq/archive/refs/tags/$LIBDAQ_SERVER_FILE_NAME \
  --output-dir $DOWNLOAD_DIR  --create-dirs -o $LIBDAQ_LOCAL_TAR_GZ_FILE_NAME || \
  (rm $DOWNLOAD_DIR/$LIBDAQ_LOCAL_TAR_GZ_FILE_NAME; exit 1)

redo-ifchange $DOWNLOAD_DIR/$LIBDAQ_LOCAL_TAR_GZ_FILE_NAME
