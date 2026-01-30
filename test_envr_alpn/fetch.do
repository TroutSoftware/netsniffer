redo-always   # we have "manual" protection of what needs to be done in this file
redo-ifchange envrc

. ./envrc

[ -d $TEST_DIR_ALPN_DOWNLOAD ] || mkdir -p $TEST_DIR_ALPN_DOWNLOAD

ALPN_URL=https://dl-cdn.alpinelinux.org/alpine/v3.23/releases/x86_64
ALPN_VERSION=3.23.2
ALPN_FILE_NAME=alpine-minirootfs-${ALPN_VERSION}-x86_64.tar.gz

# If archive doesn't exist, download it, if that fails, delete inclomplete download
[ -f $TEST_DIR_ALPN_DOWNLOAD/$ALPN_FILE_NAME ] || \
  curl -sSL $ALPN_URL/$ALPN_FILE_NAME > $TEST_DIR_ALPN_DOWNLOAD/$ALPN_FILE_NAME || \
  (rm $TEST_DIR_ALPN_DOWNLOAD/$ALPN_FILE_NAME; exit 1)

[ -d $TEST_DIR_ALPN_OS ] || (mkdir -p $TEST_DIR_ALPN_OS && ( \
  tar -C $TEST_DIR_ALPN_OS -xzf $TEST_DIR_ALPN_DOWNLOAD/$ALPN_FILE_NAME || \
  (rm -r $TEST_DIR_ALPN_OS; exit 2)))


