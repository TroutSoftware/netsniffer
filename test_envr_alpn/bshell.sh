MY_HOME="$(cd "$(dirname "$0")" && pwd)"


if [ -f "etc/alpine-release" ]; then
  if [ "$#" -eq 0 ]; then
    sh
  else
    "$@"
  fi
else
  redo-ifchange $MY_HOME/envrc $MY_HOME/config-host $MY_HOME/install
  . $MY_HOME/envrc
  . $MY_HOME/build-lib.rc

  echo Launching the build only version of Alpine...

  if [ "$#" -eq 0 ]; then
    _bwrap sh
  else
    _bwrap "$@"
  fi
fi





