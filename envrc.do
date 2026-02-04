
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


	#if [ "\$USE_LLVM_CXX_LIB" = "1" ]; then
	#  LD_LIBRARY_PATH="\$INSTALL_DIR/lib:\$INSTALL_DIR/lib64:/usr/lib/llvm21/lib:$LD_LIBRARY_PATH"
	#else
	#  LD_LIBRARY_PATH="\$INSTALL_DIR/lib:\$INSTALL_DIR/lib64:$LD_LIBRARY_PATH"
	#fi
	#if [ "\$USE_LLVM_CXX_LIB" = "1" ]; then
	#  # We want to be sure to use the llvm21 versions of tools
	#  PATH="/usr/lib/llvm21/bin:$PATH"
	#fi
	#if [ "\$USE_LLVM_CXX_LIB" = "1" ]; then
	#  CXXFLAGS="\$CFLAGS -stdlib=libc++ -fvisibility=default -fexceptions -frtti"
	#else
	#  CXXFLAGS="\$CFLAGS -stdlib=libstdc++ -fvisibility=default -fexceptions -frtti"
	#fi
	#if [ "\$USE_LLVM_CXX_LIB" = "1" ]; then
	#else
	#  LIBDAQ_CONFIG_CFLAGS=""
	#  LIBDAQ_CONFIG_CXXFLAGS=""
	#fi
	#if [ "\$USE_LLVM_CXX_LIB" = "1" ]; then
	#  LDFLAGS="-fuse-ld=lld -nodefaultlibs --rtlib=compiler-rt --unwindlib=libunwind -L/usr/lib/llvm21/lib -lc++ -lc++abi -lunwind -lm -lc -rdynamic"
  #else
	#  LDFLAGS="-fuse-ld=lld -rdynamic"
	#fi


cat > $3 <<- EOF
	# To modify this file edit $(pwd)/envrc.do


	# Export all variables to the environment
	set -a

	BASE_DIR=$(pwd)
	BUILD_DIR=\$BASE_DIR/p
	DOWNLOAD_DIR=\$BUILD_DIR/download_cache
	INSTALL_DIR=\$BUILD_DIR/install
	INSTALL_DEBUG_DIR=\$BUILD_DIR/install_debug
	LD_LIBRARY_PATH=$LD_LIBRARY_PATH
	TMP_FOLDER=\$BUILD_DIR/tmp
	PD=\$BASE_DIR/plugins
	ID=\$BASE_DIR/includes
	PATH="/usr/lib/llvm21/bin:$PATH"
	CC=clang
	CXX=clang++
	CFLAGS="-fPIC"
	CXXFLAGS="$CXXFLAGS"
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
