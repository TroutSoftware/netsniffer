#!/bin/sh

redo-ifchange envrc bootstrap/deps bootstrap/snort_build debug || exit 1

. ./envrc

echo "$INSTALL_DEBUG_DIR/bin/snort -v --warn-all --plugin-path $BUILD_DIR/debug/tm.so $*"

$INSTALL_DEBUG_DIR/bin/snort -v --warn-all --plugin-path $BUILD_DIR/debug/tm.so $*

