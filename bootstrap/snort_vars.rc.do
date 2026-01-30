redo-ifchange ../envrc version_tags.rc

. ../envrc
. ./version_tags.rc

[ -d $TMP_FOLDER ] || mkdir -p $TMP_FOLDER
exec > $TMP_FOLDER/$1

cat <<- EOF
	# To modify content of this file, edit $(pwd)/snort_vars.rc.do
	SNORT_SERVER_FILE_NAME=$snort_tag.tar.gz
	SNORT_LOCAL_TAR_GZ_FILE_NAME=snort-$snort_tag.tar.gz
	SNORT_SRC_DIR=$BUILD_DIR/snort3-$snort_tag
EOF

redo-ifchange $TMP_FOLDER/$1
