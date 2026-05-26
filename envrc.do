
#redo-always

########################################################################
# USE_LLVM_CXX_LIB=0 Use default (GNU) libraries                       #
# USE_LLVM_CXX_LIB=1 Use LLVM libraries                                #
########################################################################
USE_LLVM_CXX_LIB=0


if [ "\$USE_LLVM_CXX_LIB" = "1" ]; then
  LD_LIBRARY_PATH="/usr/lib/llvm21/lib:$LD_LIBRARY_PATH"

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

cat > $3 <<- EOF
	# To modify this file edit $(pwd)/envrc.do

# NOCOMMIT: MKR - Remove this :
	if [ -f /etc/alpine-release ]; then
		echo "WARNING: You are building Netsniffer under alpine" >&2

	fi
	echo "Remember to remove the NOCOMMIT check"

	# Export all variables to the environment
	set -a

	BASE_DIR=$(pwd)
	BUILD_DIR=${BUILD_DIR:-"\$BASE_DIR/p-alpine"}
	INSTALL_DIR=${INSTALL_DIR:-"\$BUILD_DIR/install"}
	INSTALL_DEBUG_DIR=${INSTALL_DEBUG_DIR:-\$BUILD_DIR/install_debug}
	LD_LIBRARY_PATH_RELEASE=INSTALL_DIR/lib:$LD_LIBRARY_PATH	
	LD_LIBRARY_PATH_DEBUG=INSTALL_DEBUG_DIR/lib:$LD_LIBRARY_PATH
	TMP_FOLDER=\$BUILD_DIR/tmp
	PD=\$BASE_DIR/core/src/trout_plugins
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
	TEST_ENV=\$BASE_DIR/test_envr_alpn

	# Stop exporting everything
	set +a

	_env_build() {
	  echo "Trying to launch: \$TEST_ENV/bshell.sh \$@" >&2
	  \$TEST_ENV/bshell.sh sh -c "\$@"

	}


EOF

# The output of this script depends on environment vaiables, changes of
# these can't easily be picked up by the build system
#
# These lines ensure scripts that depend on the output of this script
# are only being marked for rerun if the output of this script changes
redo-stamp < $3
redo-always
