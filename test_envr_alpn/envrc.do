


cat > $3 <<- EOF
	# To modify content of this file, edit envrc.do
	TEST_ENV="$(basename "$(pwd)")"
	BASE_DIR="$(dirname "$(pwd)")"
	BUILD_DIR="\$BASE_DIR/p"
	TEST_DIR_ALPN=\$BUILD_DIR/alpine_build
	TEST_DIR_ALPN_DOWNLOAD=\$TEST_DIR_ALPN/download
	TEST_DIR_ALPN_OS=\$TEST_DIR_ALPN/os
	TEST_DIR_BUILD=\$TEST_DIR_ALPN/p
	REDO_CACHE_ALPN_FOLDER=\$TEST_DIR_ALPN/alpine_redo_db
	GO_RUNTIME="\$TEST_DIR_ALPN/go_runtime"

	# Make sure some folders are existing
	mkdir -p \$REDO_CACHE_ALPN_FOLDER \
	         \$TEST_DIR_ALPN_DOWNLOAD \
	         \$TEST_DIR_BUILD \
	         \$REDO_CACHE_ALPN_FOLDER \
	         \$GO_RUNTIME

EOF


# Look at the actuall content of the generated file to see if it changed
redo-always
redo-stamp <$3
