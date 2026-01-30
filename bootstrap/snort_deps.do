redo-ifchange ../envrc version_tags.rc

. ../envrc
. ./version_tags.rc

exec >&2

[ -d $BUILD_DIR ] || mkdir -p $BUILD_DIR

redo-ifchange libdaq_install snort_unpack

(cd "$BUILD_DIR/snort3-$snort_tag" || exit 1;
PKG_CONFIG_PATH="$INSTALL_DIR/lib/pkgconfig:$PKG_CONFIG_PATH" cmake \
  -S "$BUILD_DIR/snort3-${snort_tag}" \
  -B "$BUILD_DIR/snort3-${snort_tag}-build" \
  -G Ninja \
  -DCMAKE_INSTALL_PREFIX="$INSTALL_DIR" \
  -DCMAKE_BUILD_TYPE=Release \
  -DENABLE_STDLOG=ON \
  -DENABLE_LUAJIT_STATIC=OFF \
  -DENABLE_STATIC_DAQ=ON \
  -DDAQ_INCLUDE_PATH="$INSTALL_DIR/include" \
  -DDAQ_LIBRARIES_PATH="$INSTALL_DIR/lib" \
  -DCMAKE_C_COMPILER="$CC" \
  -DCMAKE_CXX_COMPILER="$CXX" \
  -DCMAKE_CXX_FLAGS="$CXXFLAGS" \
  -DCMAKE_EXE_LINKER_FLAGS="$LDFLAGS" \
  -DCMAKE_SHARED_LINKER_FLAGS="$LDFLAGS" \
  -DCMAKE_CXX_STANDARD_LIBRARIES="-lc++ -lc++abi -lunwind" \
  -DCMAKE_LINKER="$LD" )

(cd "$BUILD_DIR/snort3-$snort_tag" || exit 1;
PKG_CONFIG_PATH="$INSTALL_DIR/lib/pkgconfig:$PKG_CONFIG_PATH" cmake \
  -S "$BUILD_DIR/snort3-${snort_tag}" \
  -B "$BUILD_DIR/snort3-${snort_tag}-build_debug" \
  -G Ninja \
  -DCMAKE_INSTALL_PREFIX="$INSTALL_DEBUG_DIR" \
  -DCMAKE_BUILD_TYPE=Debug \
  -DENABLE_STDLOG=ON \
  -DENABLE_LUAJIT_STATIC=OFF \
  -DENABLE_STATIC_DAQ=ON \
  -DDAQ_INCLUDE_PATH="$INSTALL_DIR/include" \
  -DDAQ_LIBRARIES_PATH="$INSTALL_DIR/lib" \
  -DCMAKE_C_COMPILER="$CC" \
  -DCMAKE_CXX_COMPILER="$CXX" \
  -DCMAKE_CXX_FLAGS="$CXXFLAGS" \
  -DCMAKE_EXE_LINKER_FLAGS="$LDFLAGS" \
  -DCMAKE_SHARED_LINKER_FLAGS="$LDFLAGS" \
  -DCMAKE_CXX_STANDARD_LIBRARIES="-lc++ -lc++abi -lunwind" \
  -DCMAKE_LINKER="$LD" )

redo-ifchange $(find $BUILD_DIR/snort3-$snort_tag -type f )
redo-ifchange $BUILD_DIR/snort3-${snort_tag}-build_debug/build.ninja
redo-ifchange $BUILD_DIR/snort3-${snort_tag}-build/build.ninja
