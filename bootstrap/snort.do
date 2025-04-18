. ../envrc

redo-ifchange libdaq

tag=3.7.2.0

curl -sL "https://github.com/snort3/snort3/archive/refs/tags/$tag.tar.gz" | tar -C "$BUILD_DIR" -xzf -

exec >&2
(cd "$BUILD_DIR/snort3-$tag" || exit;
 PKG_CONFIG_PATH="$INSTALL_DIR/lib/pkgconfig" ./configure_cmake.sh \
 --with-daq-includes="$INSTALL_DIR/include" --with-daq-libraries="$INSTALL_DIR/libdaq/lib" \
 --prefix="$INSTALL_DIR" --enable-stdlog --generator=Ninja \
 --enable-luajit-static --enable-static-daq)
(cd "$BUILD_DIR/snort3-$tag/build" || exit; ninja install)