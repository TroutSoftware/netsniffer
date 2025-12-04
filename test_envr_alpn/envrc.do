cat <<- EOF
	# To modify content of this file, edit envrc.do
	TEST_DIR_ALPN=$(pwd)
	TEST_DIR_ALPN_DOWNLOAD=\$TEST_DIR_ALPN/download
	TEST_DIR_ALPN_OS=\$TEST_DIR_ALPN/os
	TEST_DIR_BUILD=\$TEST_DIR_ALPN/p
	REDO_SRC_PATH=\${TEST_DIR_ALPN_OS}/srv/redo_src
EOF
