cat <<- EOF
	# To modify this file edit $(pwd)/envrc.do
	BASE_DIR=$(pwd)
	BUILD_DIR=\$BASE_DIR/p
	DOWNLOAD_DIR=\$BUILD_DIR/download_cache
	INSTALL_DIR=\$BUILD_DIR/install
	INSTALL_DEBUG_DIR=\$BUILD_DIR/install_debug
	TMP_FOLDER=\$BUILD_DIR/tmp
	PD=\$BASE_DIR/plugins
	ID=\$BASE_DIR/includes
EOF
