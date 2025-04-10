. ../envrc

redo-ifchange libdaq libml

tag=3.7.2.0

curl -sL "https://github.com/snort3/snort3/archive/refs/tags/$tag.tar.gz" | tar -C "$BUILD_DIR" -xzf -

exec >snort_install_log
exec 2>snort_install_log
(cd "$BUILD_DIR/snort3-$tag"; ./configure_cmake.sh --with-daq-includes="$INSTALL_DIR/include" --with-daq-libraries="$INSTALL_DIR/libdaq/lib" --with-libml-includes="$INSTALL_DIR/include" --with-libml-libraries="$INSTALL_DIR/lib" --prefix="$INSTALL_DIR")
(cd "$BUILD_DIR/snort3-$tag/build"; make -j $(nproc) install)