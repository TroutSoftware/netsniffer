redo-ifchange ../envrc snort_vars.rc

. ../envrc
. $TMP_FOLDER/snort_vars.rc

exec >&2

mkdir -p $BUILD_DIR

redo-ifchange libdaq_install libdaq_install_debug

cd "$SNORT_SRC_DIR" || exit 1;

# Debug build

CONFIG_RELEASE_LAUNCHER="$TMP_FOLDER/core.config.release.launch.sh"

cat << EOF > "$CONFIG_RELEASE_LAUNCHER"
  echo "LAUNCHING CORE RELEASE CONFIG"
  PKG_CONFIG_PATH="$INSTALL_DIR/lib/pkgconfig:$PKG_CONFIG_PATH" cmake \\
  -S "$SNORT_SRC_DIR" \\
  -B "$SNORT_BUILD_DIR" \\
  -G Ninja \\
  -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \\
  -DCMAKE_INSTALL_PREFIX="$INSTALL_DIR" \\
  -DCMAKE_BUILD_TYPE=Release \\
  -DENABLE_STDLOG=ON \\
  -DENABLE_LUAJIT_STATIC=OFF \\
  -DENABLE_STATIC_DAQ=ON \\
  -DDAQ_INCLUDE_PATH="$INSTALL_DIR/include" \\
  -DDAQ_LIBRARIES_PATH="$INSTALL_DIR/lib" \\
  -DCMAKE_C_COMPILER="$CC" \\
  -DCMAKE_CXX_COMPILER="$CXX" \\
  -DCMAKE_CXX_FLAGS="$CXXFLAGS" \\
  -DCMAKE_EXE_LINKER_FLAGS="$LDFLAGS" \\
  -DCMAKE_SHARED_LINKER_FLAGS="$LDFLAGS" \\
  -DCMAKE_LINKER="$LD"
EOF

chmod +x "$CONFIG_RELEASE_LAUNCHER"
_env_build "$CONFIG_RELEASE_LAUNCHER"


# Release build
cd "$SNORT_SRC_DIR" || exit 1
CONFIG_DEBUG_LAUNCHER="$TMP_FOLDER/core.config.debug.launch.sh"

cat << EOF > "$CONFIG_DEBUG_LAUNCHER"
  echo "LAUNCHING CORE DEBUG CONFIG"
  PKG_CONFIG_PATH="$INSTALL_DIR_DEBUG/lib/pkgconfig:$PKG_CONFIG_PATH" cmake \\
  -S "$SNORT_SRC_DIR" \\
  -B "$SNORT_BUILD_DIR_DEBUG" \\
  -G Ninja \\
  -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \\
  -DCMAKE_INSTALL_PREFIX="$INSTALL_DEBUG_DIR" \\
  -DCMAKE_BUILD_TYPE=Debug \\
  -DENABLE_STDLOG=ON \\
  -DENABLE_LUAJIT_STATIC=OFF \\
  -DENABLE_STATIC_DAQ=ON \\
  -DDAQ_INCLUDE_PATH="$INSTALL_DIR_DEBUG/include" \\
  -DDAQ_LIBRARIES_PATH="$INSTALL_DIR_DEBUG/lib" \\
  -DCMAKE_C_COMPILER="$CC" \\
  -DCMAKE_CXX_COMPILER="$CXX" \\
  -DCMAKE_CXX_FLAGS="$CXXFLAGS" \\
  -DCMAKE_EXE_LINKER_FLAGS="$LDFLAGS" \\
  -DCMAKE_SHARED_LINKER_FLAGS="$LDFLAGS" \\
  -DCMAKE_LINKER="$LD"
EOF

chmod +x "$CONFIG_DEBUG_LAUNCHER"
_env_build "$CONFIG_DEBUG_LAUNCHER"

redo-ifchange $(find $BASE_DIR/core -type f)
redo-ifchange $SNORT_BUILD_DIR/build.ninja
redo-ifchange $SNORT_BUILD_DIR_DEBUG/build.ninja

cp $SNORT_BUILD_DIR_DEBUG/compile_commands.json $TMP_FOLDER/compile_commands.core

redo-ifchange $TMP_FOLDER/compile_commands.core
redo-ifchange $SNORT_BUILD_DIR_DEBUG/compile_commands.json
