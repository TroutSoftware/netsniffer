#!/bin/sh

redo-ifchange envrc bootstrap/deps bootstrap/snort_build debug || exit 1

. ./envrc

# Explicitly set the DAQ directory so Snort finds the modules automatically
DAQ_LIB_DIR="$INSTALL_DIR/lib/daq"

echo "$INSTALL_DEBUG_DIR/bin/snort -v --warn-all --daq-dir $DAQ_LIB_DIR --plugin-path $BUILD_DIR/debug/tm.so $*"

$INSTALL_DEBUG_DIR/bin/snort \
    -v \
    --warn-all \
    --daq-dir "$DAQ_LIB_DIR" \
    --plugin-path "$BUILD_DIR/debug/tm.so" \
    "$@"
