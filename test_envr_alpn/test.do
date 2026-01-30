echo "This script is not supported, run ./bshell.sh to enter the configured environment" >&2

exit 0

redo-ifchange envrc config-host install build-lib.rc

. ./envrc

. ./build-lib.rc

_bwrap redo test >&2


