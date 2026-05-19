
########################################################################
# USE_LLVM_CXX_LIB=0 Use default (GNU) libraries                       #
# USE_LLVM_CXX_LIB=1 Use LLVM libraries                                #
########################################################################
USE_LLVM_CXX_LIB=0


if [ "\$USE_LLVM_CXX_LIB" = "1" ]; then
  LD_LIBRARY_PATH="\$INSTALL_DIR/lib:\$INSTALL_DIR/lib64:/usr/lib/llvm21/lib:$LD_LIBRARY_PATH"

  CXXFLAGS="\$CFLAGS -stdlib=libc++ -fvisibility=default -fexceptions -frtti"

  # Specifically for libdaq, couldn't make it work with linker flags
  LIBDAQ_CONFIG_CFLAGS="--rtlib=compiler-rt --unwindlib=libunwind"
  LIBDAQ_CONFIG_CXXFLAGS="--rtlib=compiler-rt --unwindlib=libunwind"
  LDFLAGS="-fuse-ld=lld -nodefaultlibs --rtlib=compiler-rt --unwindlib=libunwind -L/usr/lib/llvm21/lib -lc++ -lc++abi -lunwind -lm -lc -rdynamic"
else
  LD_LIBRARY_PATH="\$INSTALL_DIR/lib:\$INSTALL_DIR/lib64:$LD_LIBRARY_PATH"
  CXXFLAGS="\$CFLAGS -stdlib=libstdc++ -fvisibility=default -fexceptions -frtti"
  LIBDAQ_CONFIG_CFLAGS=""
  LIBDAQ_CONFIG_CXXFLAGS=""
  LDFLAGS="-fuse-ld=lld -rdynamic"
fi

if [ ! -f /etc/alpine-release ]; then
  echo "ERROR: netsniffer can only be build and run under Alpine, change to ./test_envr_alpn and run ./bshell.sh to get an Alpine prompt" >&2
  exit 1
fi

cat > $3 <<- EOF
	# To modify this file edit $(pwd)/envrc.do

	if [ ! -f /etc/alpine-release ]; then
		echo "ERROR: netsniffer can only be build and run under Alpine, change to ./test_envr_alpn and run ./bshell.sh to get an Alpine prompt" >&2
		exit 1
	fi

	# Export all variables to the environment
	set -a

	BASE_DIR=$(pwd)
	BUILD_DIR=${BUILD_DIR:-"\$BASE_DIR/p"}
	DOWNLOAD_DIR=\$BUILD_DIR/download_cache
	INSTALL_DIR=${INSTALL_DIR:-"\$BUILD_DIR/install"}
	INSTALL_DEBUG_DIR=\$BUILD_DIR/install_debug
	LD_LIBRARY_PATH=$LD_LIBRARY_PATH
	TMP_FOLDER=\$BUILD_DIR/tmp
	PD=\$BASE_DIR/core/src/trout_plugins
	ID=\$BASE_DIR/includes
	PATH="/usr/lib/llvm21/bin:$PATH"
	CC=clang
	CXX=clang++
	CFLAGS="-fPIC"
	CXXFLAGS="$CXXFLAGS -std=c++23"
	LIBDAQ_CONFIG_CFLAGS="$LIBDAQ_CONFIG_CFLAGS"
	LIBDAQ_CONFIG_CXXFLAGS="$LIBDAQ_CONFIG_CXXFLAGS"
	LDFLAGS="$LDFLAGS"
	LD=ld.lld
	AR=llvm-ar
	NM=llvm-nm
	RANLIB=llvm-ranlib
	STRIP=llvm-strip

	# Stop exporting everything
	set +a
EOF

# The output of this script depends on environment vaiables, changes of
# these can't easily be picked up by the build system
#
# These lines ensure scripts that depend on the output of this script
# are only being marked for rerun if the output of this script changes

redo-always
redo-stamp <$3
