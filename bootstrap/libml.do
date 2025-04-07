. ../envrc

tag=2.0.0

curl -sL "https://github.com/snort3/libml/archive/refs/tags/$tag.tar.gz" | tar -C "$BUILD_DIR" -xzf  -

exec >libml_install_log
exec 2>libml_install_log
(cd "$BUILD_DIR/libml-$tag"; ./configure.sh --prefix="$INSTALL_DIR")
(cd "$BUILD_DIR/libml-$tag/build"; make install/strip)