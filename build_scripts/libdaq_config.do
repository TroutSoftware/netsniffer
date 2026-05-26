redo-ifchange ../envrc libdaq_vars.rc

exec >&2

. ../envrc
. $TMP_FOLDER/libdaq_vars.rc


cd "$LIBDAQ_SRC_DIR" || exit 1;
_env_build ./bootstrap


#[ -d $BUILD_DIR ] || mkdir -p $BUILD_DIR

mkdir -p \
   $LIBDAQ_BUILD_DIR \
   $LIBDAQ_BUILD_DIR_DEBUG \
   $INSTALL_DIR \
   $INSTALL_DEBUG_DIR



# Release build
cd $LIBDAQ_BUILD_DIR
CONFIG_LAUNCHER="$TMP_FOLDER/libdaq.config_release.launch.sh"

cat << EOF > "$CONFIG_LAUNCHER"
# Inject the runtime flags directly into the compiler variable
# This prevents libtool from stripping them out
CC="$CC $LIBDAQ_CONFIG_CFLAGS" \\
CXX="$CXX $LIBDAQ_CONFIG_CXXFLAGS" \\
CFLAGS="$CFLAGS" \\
CXXFLAGS="$CXXFLAGS" \\
LDFLAGS="$LDFLAGS" \\
$LIBDAQ_SRC_DIR/configure \\
  --prefix="$INSTALL_DIR" \\
  --enable-shared \\
  --enable-static
EOF

chmod +x "$CONFIG_LAUNCHER"
_env_build "$CONFIG_LAUNCHER"


# Debug build
cd $LIBDAQ_BUILD_DIR_DEBUG
CONFIG_DEBUG_LAUNCHER="$TMP_FOLDER/libdaq.config_debug.launch.sh"

cat << EOF > "$CONFIG_DEBUG_LAUNCHER"
# Inject the runtime flags directly into the compiler variable
# This prevents libtool from stripping them out
CC="$CC $LIBDAQ_CONFIG_CFLAGS" \\
CXX="$CXX $LIBDAQ_CONFIG_CXXFLAGS" \\
CFLAGS="$CFLAGS -Og -glldb" \\
CXXFLAGS="$CXXFLAGS -Og -glldb" \\
LDFLAGS="$LDFLAGS" \\
$LIBDAQ_SRC_DIR/configure \\
  --prefix="$INSTALL_DEBUG_DIR" \\
  --enable-shared \\
  --enable-static
EOF

chmod +x "$CONFIG_DEBUG_LAUNCHER"
_env_build "$CONFIG_DEBUG_LAUNCHER"

echo "Checking $LIBDAQ_BUILD_DIR/Makefile"
echo "Checking $LIBDAQ_BUILD_DIR_DEBUG/Makefile"
redo-ifchange $LIBDAQ_BUILD_DIR/Makefile
redo-ifchange $LIBDAQ_BUILD_DIR_DEBUG/Makefile

