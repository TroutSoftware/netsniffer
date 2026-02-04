

redo-ifchange envrc config-host install
. ./envrc
. ./build-lib.rc

echo launching...

_bwrap sh "$@"




