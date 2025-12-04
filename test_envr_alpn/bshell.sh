

redo-ifchange envrc ../envrc config-host install

. ../envrc
. ./envrc

. ./build-lib.rc

_bwrap sh "$@"
