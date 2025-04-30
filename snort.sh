#!/bin/sh

redo-ifchange envrc debug  || exit 1

. ./envrc

echo "$INSTALL_DIR/bin/snort --plugin-path $BUILD_DIR/debug/tm.so $*"

$INSTALL_DIR/bin/snort -v --warn-all --plugin-path $BUILD_DIR/debug/tm.so $*

