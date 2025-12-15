# We should also check if the install dir is updated...

redo-ifchange ../envrc libdaq_vars.rc libdaq_config
find $LIBDAQ_SRC_DIR -type f | xargs redo-ifchange

exec >&2

. ../envrc
. $TMP_FOLDER/libdaq_vars.rc

cd $LIBDAQ_BUILD_DIR

make install

#redo-ifchange $(find $LIBDAQ_BUILD_DIR -type f )
find $LIBDAQ_BUILD_DIR -type f | xargs redo-ifchange

# This is just an approximation
#redo-ifchange $(find $INSTALL_DIR -type f -iname *libdaq*)
find $INSTALL_DIR -type f -iname "*libdaq*" | xargs redo-ifchange
