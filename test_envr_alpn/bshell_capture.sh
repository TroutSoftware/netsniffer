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

  echo "Launching the network capture enabled version of Alpine..."
  echo "(This runs a SUDO command to launch Alpine, you might need"
  echo "to enter your password)"

  if [ "$#" -eq 0 ]; then
    _bwrap_sudo sh
  else
    _bwrap_sudo "$@"
  fi
fi
