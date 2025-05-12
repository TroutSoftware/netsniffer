#!/bin/sh

redo-ifchange envrc debug

if [ $? -eq 0 ]; then
  . ./envrc
  
  gdb --args $INSTALL_DIR/bin/snort -v --plugin-path $BUILD_DIR/debug/tm.so $*
else
  echo "Build issues found, check log for errors"
fi
