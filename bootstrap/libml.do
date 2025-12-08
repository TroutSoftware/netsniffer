# We rely on make to determine if anything should be done
redo-always
redo-ifchange ../envrc libml_src libml_src_config libml_vars

exec >&2

. ../envrc
. $TMP_FOLDER/libml_vars

cd $LIBML_BUILD_DIR
make install
