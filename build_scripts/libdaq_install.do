# We should also check if the install dir is updated...

exec >&2

redo-ifchange ../envrc libdaq_vars.rc libdaq_config
. ../envrc
. $TMP_FOLDER/libdaq_vars.rc

cd $LIBDAQ_BUILD_DIR

_env_build "make install"

# We depend on all the generated files
find $LIBDAQ_BUILD_DIR -type f | xargs redo-ifchange

# This is just an approximation
find $INSTALL_DIR -type f -iname "*libdaq*" | xargs redo-ifchange

# We depend on all the source files
find $LIBDAQ_SRC_DIR -type f | xargs redo-ifchange


