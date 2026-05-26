redo-always  # This should always be rebuild as we rely on ninja to do the actual work

redo-ifchange ../envrc snort_config snort_vars.rc libdaq_install

. ../envrc
. $TMP_FOLDER/snort_vars.rc

exec >&2

cd "$SNORT_BUILD_DIR" || exit 1
_env_build "ninja install"


