redo-always  # This should always be rebuild as we rely on ninja to do the actual work

redo-ifchange ../envrc snort_config snort_vars.rc libdaq_install_debug

. ../envrc
. $TMP_FOLDER/snort_vars.rc

exec >&2

(cd "$SNORT_BUILD_DIR_DEBUG" || exit 1; ninja install)
