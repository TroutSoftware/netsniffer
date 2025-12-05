redo-ifchange ../envrc version_tags

exec >libml.log
exec 2>>libml.log

. ../envrc
. ./version_tags

BUILD_BUILD_DIR=$BUILD_DIR/libml-$libml_tag-build
BUILD_SRC_DIR=$BUILD_DIR/libml-$libml_tag


curl -sL https://github.com/snort3/libml/archive/refs/tags/$libml_tag.tar.gz | tar -C "$BUILD_DIR" -xzf  -


#find "$BUILD_DIR/libml-$libml_tag" -type f | xargs redo-ifchange


(cd "$BUILD_SRC_DIR" || exit 1;
	./configure.sh --debugrelease --prefix="$INSTALL_DIR" --builddir=$BUILD_BUILD_DIR;
	cd $BUILD_BUILD_DIR; make;	make install)


redo-ifchange "$INSTALL_DIR"/lib/libml.so
