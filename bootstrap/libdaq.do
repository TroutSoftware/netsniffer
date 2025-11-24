redo-ifchange ../envrc version_tags

. ../envrc
. ./version_tags

curl -sL https://github.com/snort3/libdaq/archive/refs/tags/v$libdaq_tag.tar.gz | tar -C "$BUILD_DIR" -xzf  -

redo-ifchange $(find -type f $BUILD_DIR/libdaq-$libdaq_tag)

exec >libdaq_install_log
exec 2>libdaq_install_log
(cd "$BUILD_DIR/libdaq-$libdaq_tag" || exit;
	./bootstrap;
	./configure --prefix="$INSTALL_DIR" ;
	make;	make install)

redo-ifchange "$INSTALL_DIR"/lib/libdaq.so.3.0.0
