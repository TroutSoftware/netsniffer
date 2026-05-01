redo-ifchange ../envrc

. ../envrc

[ -d $TMP_FOLDER ] || mkdir -p $TMP_FOLDER
exec > $TMP_FOLDER/$1

cat <<- EOF
	# To modify content of this file, edit $(pwd)/libdaq_vars.rc.do
	# Currently libdaq doesn't support seperate build dirs (without patching it)
	LIBDAQ_BUILD_DIR=$BUILD_DIR/daq_release
	LIBDAQ_BUILD_DIR_DEBUG=$BUILD_DIR/daq_debug
	LIBDAQ_SRC_DIR=$BASE_DIR/daq
EOF

redo-ifchange $TMP_FOLDER/$1
