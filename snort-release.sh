#!/bin/sh

redo-ifchange envrc release || exit 1

. ./envrc

# Explicitly set the DAQ directory so Snort finds the modules automatically
DAQ_LIB_DIR="$INSTALL_DIR/lib/daq"

set -x
$INSTALL_DIR/bin/snort -v --warn-all --daq-dir $DAQ_LIB_DIR "$@"

