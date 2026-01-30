# Checks the host has the dependencies

redo-always # we manually check things in this file

redo-ifchange envrc packages-host

. ./envrc

[ -f /etc/apparmor.d/usr.bin.bwrap ]  || (\
  echo "Please copy the file 'bwrap' from $TEST_DIR_ALPN to /etc/apparmor.d/usr.bin.bwrap and restart apparmor 'sudo /etc/init.d/apparmor restart'" >&2 \
  && exit 1)

[ -f /etc/apparmor.d/usr.bin.unshare ]  || (\
  echo "Please copy the file 'usr.bin.unshare' from $TEST_DIR_ALPN to /etc/apparmor.d and restart apparmor 'sudo /etc/init.d/apparmor restart'" >&2 \
  && exit 1)

cat packages-host| grep -v "^#" | xargs ./test_package_installed.sh || \
  (echo "Please install mentioned packages from $TEST_DIR_ALPN/packages-host" >&2 && exit 1)
