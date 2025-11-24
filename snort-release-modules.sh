#!/bin/sh

redo-ifchange envrc bootstrap/deps bootstrap/snort_build release || exit 1

. ./envrc

echo "$INSTALL_DIR/bin/snort -v --warn-all --plugin-path $BUILD_DIR/release/tm.so $*"

$INSTALL_DIR/bin/snort -v --warn-all --plugin-path $BUILD_DIR/release/tm.so $*

