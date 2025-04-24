#!/bin/sh

redo-ifchange envrc

. ./envrc

redo debug  # this can't be redo-ifchange as it MUST invoke Ninja

$INSTALL_DIR/bin/snort --plugin-path $BUILD_DIR/debug/tm.so $*
