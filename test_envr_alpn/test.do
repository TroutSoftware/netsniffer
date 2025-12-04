redo-ifchange envrc ../envrc config-host install build-lib.rc

. ../envrc
. ./envrc

. ./build-lib.rc

_bwrap redo test >&2
