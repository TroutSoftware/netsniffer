redo-ifchange ../envrc libml_vars.rc libml_unpack

exec >&2

. ../envrc
. $TMP_FOLDER/libml_vars.rc

cd "$LIBML_SRC_DIR" || exit 1;
./configure.sh --debugrelease --prefix="$INSTALL_DIR" --builddir=$LIBML_BUILD_DIR;

redo-ifchange $LIBML_BUILD_DIR/Makefile
