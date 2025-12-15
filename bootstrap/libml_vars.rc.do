redo-ifchange ../envrc version_tags.rc

. ../envrc
. ./version_tags.rc

[ -d $TMP_FOLDER ] || mkdir -p $TMP_FOLDER
exec > $TMP_FOLDER/$1

cat <<- EOF
	# To modify content of this file, edit $(pwd)/libml_vars.do
	LIBML_SERVER_FILE_NAME=$libml_tag.tar.gz
	LIBDAQ_LOCAL_TAR_GZ_FILE_NAME=libml-$libml_tag.tar.gz
	LIBML_BUILD_DIR=$BUILD_DIR/libml-$libml_tag-build
	#LIBML_BUILD_DIR=$BUILD_DIR/libml-$libml_tag
	LIBML_SRC_DIR=$BUILD_DIR/libml-$libml_tag
EOF

redo-ifchange $TMP_FOLDER/$1
