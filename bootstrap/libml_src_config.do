redo-ifchange ../envrc libml_src libml_vars

exec >&2

. ../envrc
. $TMP_FOLDER/libml_vars

cd "$LIBML_SRC_DIR" || exit 1;
./configure.sh --debugrelease --prefix="$INSTALL_DIR" --builddir=$LIBML_BUILD_DIR;

redo-ifchange $LIBML_BUILD_DIR/Makefile
