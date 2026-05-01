redo-ifchange ../envrc libdaq_vars.rc

exec >&2

. ../envrc
. $TMP_FOLDER/libdaq_vars.rc

cd "$LIBDAQ_SRC_DIR" || exit 1;
./bootstrap

#[ -d $BUILD_DIR ] || mkdir -p $BUILD_DIR

[ -d $LIBDAQ_BUILD_DIR ] || mkdir -p $LIBDAQ_BUILD_DIR
[ -d $LIBDAQ_BUILD_DIR_DEBUG ] || mkdir -p $LIBDAQ_BUILD_DIR_DEBUG

# Release build
cd $LIBDAQ_BUILD_DIR

# Inject the runtime flags directly into the compiler variable
# This prevents libtool from stripping them out
CC="$CC $LIBDAQ_CONFIG_CFLAGS" \
CXX="$CXX $LIBDAQ_CONFIG_CXXFLAGS" \
CFLAGS="$CFLAGS" \
CXXFLAGS="$CXXFLAGS" \
LDFLAGS="$LDFLAGS" \
$LIBDAQ_SRC_DIR/configure \
  --prefix="$INSTALL_DIR" \
  --enable-shared \
  --enable-static

# Debug build
cd $LIBDAQ_BUILD_DIR_DEBUG

# Inject the runtime flags directly into the compiler variable
# This prevents libtool from stripping them out
CC="$CC $LIBDAQ_CONFIG_CFLAGS" \
CXX="$CXX $LIBDAQ_CONFIG_CXXFLAGS" \
CFLAGS="$CFLAGS -Og -glldb" \
CXXFLAGS="$CXXFLAGS -Og -glldb" \
LDFLAGS="$LDFLAGS" \
$LIBDAQ_SRC_DIR/configure \
  --prefix="$INSTALL_DEBUG_DIR" \
  --enable-shared \
  --enable-static


redo-ifchange $LIBDAQ_BUILD_DIR/Makefile
redo-ifchange $LIBDAQ_BUILD_DIR_DEBUG/Makefile

