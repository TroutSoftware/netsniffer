cat <<- EOF
	BUILD_DIR=$(pwd)/p
	INSTALL_DIR=${INSTALL_DIR:-"$(pwd)/p/install"}
	INSTALL_DEBUG_DIR=${INSTALL_DEBUG_DIR:-"$(pwd)/p/install_debug"}
	PD=$(pwd)/plugins
	ID=$(pwd)/includes
EOF