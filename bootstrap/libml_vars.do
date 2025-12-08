redo-ifchange version_tags ../envrc

. ../envrc
. ./version_tags

[ -d $TMP_FOLDER ] || mkdir -p $TMP_FOLDER
exec > $TMP_FOLDER/$1

cat <<- EOF
	# To modify content of this file, edit libml_vars.do
	LIBML_TAR_GZ_FILE_NAME=libml-$libml_tag.tar.gz
	LIBML_BUILD_DIR=$BUILD_DIR/libml-$libml_tag-build
	LIBML_SRC_DIR=$BUILD_DIR/libml-$libml_tag
EOF

redo-ifchange $TMP_FOLDER/$1
