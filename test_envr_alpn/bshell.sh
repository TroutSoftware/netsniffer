MY_HOME="$(cd "$(dirname "$0")" && pwd)"

redo-ifchange $MY_HOME/envrc $MY_HOME/config-host $MY_HOME/install
. $MY_HOME/envrc
. $MY_HOME/build-lib.rc

echo launching...

_bwrap sh "$@"




