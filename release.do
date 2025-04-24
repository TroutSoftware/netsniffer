redo-ifchange envrc

. ./envrc
redo-ifchange configure plugins.list $PD/snort_plugins.cc
for m in $(cat plugins.list); do echo "$PD/$m/files.list"; done | xargs redo-ifchange

mkdir -p $BUILD_DIR/release
CFLAGS="-O2" ./configure > $BUILD_DIR/release/build.ninja
ninja -C $BUILD_DIR/release >&2
redo-ifchange $BUILD_DIR/release/tm.so # detect manual clean
