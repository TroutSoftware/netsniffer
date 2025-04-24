redo-ifchange envrc

. ./envrc
#redo-ifchange configure plugins.list $PD/snort_plugins.cc
redo-ifchange configure plugins.list 
for m in $(cat plugins.list); do echo "$PD/$m/files.list"; done | xargs redo-ifchange

mkdir -p $BUILD_DIR/debug
CFLAGS="-O1 -g" ./configure > $BUILD_DIR/debug/build.ninja
