#!/bin/sh

redo-ifchange envrc bootstrap/deps bootstrap/snort_build debug || exit 1

. ./envrc

echo gdb --args $INSTALL_DEBUG_DIR/bin/snort -v --plugin-path $BUILD_DIR/debug/tm.so $*

gdb --args $INSTALL_DEBUG_DIR/bin/snort -v --plugin-path $BUILD_DIR/debug/tm.so $*
