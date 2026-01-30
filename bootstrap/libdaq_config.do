redo-ifchange ../envrc libdaq_vars.rc libdaq_unpack

exec >&2

. ../envrc
. $TMP_FOLDER/libdaq_vars.rc


cd "$LIBDAQ_SRC_DIR" || exit 1;
./bootstrap

# Inject the runtime flags directly into the compiler variable
# This prevents libtool from stripping them out
CC="$CC --rtlib=compiler-rt --unwindlib=libunwind" \
CXX="$CXX --rtlib=compiler-rt --unwindlib=libunwind" \
CFLAGS="$CFLAGS" \
CXXFLAGS="$CXXFLAGS" \
LDFLAGS="$LDFLAGS" \
./configure \
  --prefix="$INSTALL_DIR" \
  --enable-shared \
  --enable-static


redo-ifchange $LIBDAQ_BUILD_DIR/Makefile

