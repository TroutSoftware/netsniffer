redo-ifchange envrc

. ./envrc

redo-always

if [ -d $TEST_DIR_ALPN_OS ]; then
  #find $TEST_DIR_ALPN_OS -type f -exec sha1sum {} +
  find $TEST_DIR_ALPN_OS -type f
fi | sort | redo-stamp
