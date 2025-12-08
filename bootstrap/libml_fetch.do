redo-ifchange ../envrc version_tags libml_vars

exec >&2

. ../envrc
. ./version_tags
. $TMP_FOLDER/libml_vars

curl -sL https://github.com/snort3/libml/archive/refs/tags/$libml_tag.tar.gz \
  --output-dir $DOWNLOAD_DIR  --create-dirs -o $LIBML_TAR_GZ_FILE_NAME || \
  (rm $DOWNLOAD_DIR/$LIBML_TAR_GZ_FILE_NAME; exit 1)

redo-ifchange $DOWNLOAD_DIR/$LIBML_TAR_GZ_FILE_NAME
