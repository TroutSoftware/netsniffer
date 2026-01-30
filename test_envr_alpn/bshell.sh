

#redo-ifchange envrc ../envrc config-host install
redo-ifchange envrc config-host install

#. ../envrc
. ./envrc



. ./build-lib.rc

# until we move this out of the test_envr we need to regnerate it under bwrap
rm ./envrc

_bwrap sh "$@"


# and the one generated inside should not live outside
rm ./envrc
