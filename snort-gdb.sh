#!/bin/sh

redo-ifchange envrc debug || exit 1

. ./envrc

echo gdb --args $INSTALL_DIR/bin/snort -v --plugin-path $BUILD_DIR/debug/tm.so $*

gdb --args $INSTALL_DIR/bin/snort -v --plugin-path $BUILD_DIR/debug/tm.so $*
