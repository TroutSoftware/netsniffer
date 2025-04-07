redo-ifchange envrc

. ./envrc
redo-ifchange configure plugins.list
for m in $(cat plugins.list); do echo "$PD/$m/files.list"; done | xargs redo-ifchange

mkdir -p p/debug
CFLAGS="-O1 -g" ./configure > p/debug/build.ninja
ninja -C p/debug >&2