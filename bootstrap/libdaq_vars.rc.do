redo-ifchange ../envrc version_tags.rc

. ../envrc
. ./version_tags.rc

[ -d $TMP_FOLDER ] || mkdir -p $TMP_FOLDER
exec > $TMP_FOLDER/$1

cat <<- EOF
	# To modify content of this file, edit $(pwd)/libdaq_vars.rc.do
	LIBDAQ_SERVER_FILE_NAME=v$libdaq_tag.tar.gz
	LIBDAQ_LOCAL_TAR_GZ_FILE_NAME=libdaq-$libdaq_tag.tar.gz
	# Currently libdaq doesn't support seperate build dirs (without patching it)
	LIBDAQ_BUILD_DIR=$BUILD_DIR/libdaq-$libdaq_tag
	LIBDAQ_SRC_DIR=$BUILD_DIR/libdaq-$libdaq_tag
EOF

redo-ifchange $TMP_FOLDER/$1
