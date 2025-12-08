redo-ifchange ../envrc version_tags

. ../envrc
. ./version_tags

exec >snort_deps.log
exec 2>>snort_deps.log

[ -d $BUILD_DIR ] || mkdir -p $BUILD_DIR

redo-ifchange libdaq libml snort_fetch

(cd "$BUILD_DIR/snort3-$snort_tag" || exit 1;
 PKG_CONFIG_PATH="$INSTALL_DIR/lib/pkgconfig" ./configure_cmake.sh \
 --with-daq-includes="$INSTALL_DIR/include" --with-daq-libraries="$INSTALL_DIR/libdaq/lib" \
 --with-libml-includes="$INSTALL_DIR/include"  --with-libml-libraries="$INSTALL_DIR/libml/lib" \
 --prefix="$INSTALL_DEBUG_DIR" --enable-stdlog --generator=Ninja \
 --enable-luajit-static --enable-static-daq --build-type=Debug \
 --builddir="$BUILD_DIR/snort3-${snort_tag}-build_debug")

(cd "$BUILD_DIR/snort3-$snort_tag" || exit 1;
  PKG_CONFIG_PATH="$INSTALL_DIR/lib/pkgconfig" ./configure_cmake.sh \
 --with-daq-includes="$INSTALL_DIR/include" --with-daq-libraries="$INSTALL_DIR/libdaq/lib" \
 --with-libml-includes="$INSTALL_DIR/include"  --with-libml-libraries="$INSTALL_DIR/libml/lib" \
 --prefix="$INSTALL_DIR" --enable-stdlog --generator=Ninja \
 --enable-luajit-static --enable-static-daq --build-type=Release \
 --builddir="$BUILD_DIR/snort3-${snort_tag}-build")

redo-ifchange $(find -type f $BUILD_DIR/snort3-$snort_tag)
