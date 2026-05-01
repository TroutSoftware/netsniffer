redo-ifchange ../envrc

. ../envrc

[ -d $TMP_FOLDER ] || mkdir -p $TMP_FOLDER
exec > $TMP_FOLDER/$1

cat <<- EOF
	# To modify content of this file, edit $(pwd)/snort_vars.rc.do
	SNORT_BUILD_DIR=$BUILD_DIR/core_release
	SNORT_BUILD_DIR_DEBUG=$BUILD_DIR/core_debug
	SNORT_SRC_DIR=$BASE_DIR/core
EOF

redo-ifchange $TMP_FOLDER/$1
