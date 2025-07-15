cat <<- EOF
	BUILD_DIR=$(pwd)/p
	INSTALL_DIR=${INSTALL_DIR:-"$(pwd)/p/install"}
	PD=$(pwd)/plugins
	ID=$(pwd)/includes
EOF