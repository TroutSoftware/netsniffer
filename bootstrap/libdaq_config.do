redo-ifchange ../envrc libdaq_vars.rc libdaq_unpack

exec >&2

. ../envrc
. $TMP_FOLDER/libdaq_vars.rc

cd "$LIBDAQ_SRC_DIR" || exit 1;
./bootstrap
./configure --prefix="$INSTALL_DIR"

redo-ifchange $LIBDAQ_BUILD_DIR/Makefile

