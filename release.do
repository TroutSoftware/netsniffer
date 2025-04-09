redo-ifchange envrc

. ./envrc
redo-ifchange configure plugins.list $PD/snort_plugins.cc
for m in $(cat plugins.list); do echo "$PD/$m/files.list"; done | xargs redo-ifchange

mkdir -p p/release
CFLAGS="-O2" ./configure > p/release/build.ninja
ninja -C p/release >&2
redo-ifchange p/release/tm.so # detect manual clean