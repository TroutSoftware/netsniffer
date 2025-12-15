
redo-ifchange ../envrc libml_vars.rc libml_config

redo-ifchange $(find -type f $LIBML_SRC_DIR)

exec >&2

. ../envrc
. $TMP_FOLDER/libml_vars.rc

cd $LIBML_BUILD_DIR

# make install does the right thing, but is on the slow side, so doing
# the tests for changes in LBML_SRC_DIR and LIBML_BUILD_DIR
make install

redo-ifchange $(find -type f $LIBLM_BUILD_DIR)

# This is just an aproximation
redo-ifchange $(find $INSTALL_DIR -type f -iname *libml*)

