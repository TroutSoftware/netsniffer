. ../envrc

tag=3.0.19
curl -sL https://github.com/snort3/libdaq/archive/refs/tags/v$tag.tar.gz | tar -C "$BUILD_DIR" -xzf  -

exec >libdaq_install_log
exec 2>libdaq_install_log
(cd "$BUILD_DIR/libdaq-$tag" || exit; 
	./bootstrap;
	./configure --prefix="$INSTALL_DIR" ;
	make;	make install)

redo-ifchange "$INSTALL_DIR"/lib/libdaq.so.3.0.0