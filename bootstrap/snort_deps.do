redo-ifchange ../envrc version_tags.rc

. ../envrc
. ./version_tags.rc

exec >&2

[ -d $BUILD_DIR ] || mkdir -p $BUILD_DIR

redo-ifchange libdaq_install snort_fetch

(cd "$BUILD_DIR/snort3-$snort_tag" || exit 1;
 PKG_CONFIG_PATH="$INSTALL_DIR/lib/pkgconfig" ./configure_cmake.sh \
 --with-daq-includes="$INSTALL_DIR/include" --with-daq-libraries="$INSTALL_DIR/libdaq/lib" \
 --prefix="$INSTALL_DEBUG_DIR" --enable-stdlog --generator=Ninja \
 --enable-luajit-static --enable-static-daq --build-type=Debug \
 --builddir="$BUILD_DIR/snort3-${snort_tag}-build_debug")

(cd "$BUILD_DIR/snort3-$snort_tag" || exit 1;
  PKG_CONFIG_PATH="$INSTALL_DIR/lib/pkgconfig" ./configure_cmake.sh \
 --with-daq-includes="$INSTALL_DIR/include" --with-daq-libraries="$INSTALL_DIR/libdaq/lib" \
 --prefix="$INSTALL_DIR" --enable-stdlog --generator=Ninja \
 --enable-luajit-static --enable-static-daq --build-type=Release \
 --builddir="$BUILD_DIR/snort3-${snort_tag}-build")

redo-ifchange $(find -type f $BUILD_DIR/snort3-$snort_tag)
