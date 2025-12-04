redo-always   # we have "manual" protection of what needs to be done in this file
redo-ifchange envrc

. ./envrc

[ -d $TEST_DIR_ALPN_DOWNLOAD ] || mkdir -p $TEST_DIR_ALPN_DOWNLOAD

ALPN_URL=https://dl-cdn.alpinelinux.org/alpine/v3.22/releases/x86_64
ALPN_VERSION=3.22.2
ALPN_FILE_NAME=alpine-minirootfs-${ALPN_VERSION}-x86_64.tar.gz

# If archive doesn't exist, download it, if that fails, delete inclomplete download
[ -f $TEST_DIR_ALPN_DOWNLOAD/$ALPN_FILE_NAME ] || \
  curl -sSL $ALPN_URL/$ALPN_FILE_NAME > $TEST_DIR_ALPN_DOWNLOAD/$ALPN_FILE_NAME || \
  (rm $TEST_DIR_ALPN_DOWNLOAD/$ALPN_FILE_NAME; exit 1)

[ -d $TEST_DIR_ALPN_OS ] || (mkdir -p $TEST_DIR_ALPN_OS && ( \
  tar -C $TEST_DIR_ALPN_OS -xzf $TEST_DIR_ALPN_DOWNLOAD/$ALPN_FILE_NAME || \
  (rm -r $TEST_DIR_ALPN_OS; exit 2)))

REDO_URL=https://github.com/apenwarr/redo/archive/refs/tags/
REDO_VERSION=0.42d
REDO_FILE_PREFIX=redo-${REDO_VERSION}
REDO_FILE_NAME=${REDO_FILE_PREFIX}.tar.gz
REDO_FILE_PATH=redo-${REDO_FILE_PREFIX}

[ -f $TEST_DIR_ALPN_DOWNLOAD/$REDO_FILE_NAME ] || \
  curl -sSL $REDO_URL/$REDO_FILE_NAME > $TEST_DIR_ALPN_DOWNLOAD/$REDO_FILE_NAME || \
  (rm $TEST_DIR_ALPN_DOWNLOAD/$REDO_FILE_NAME; exit 3)

[ -d REDO_SRC_PATH ] || (mkdir -p $REDO_SRC_PATH && (\
  tar -C $REDO_SRC_PATH -xzf $TEST_DIR_ALPN_DOWNLOAD/$REDO_FILE_NAME --strip-components=1 || \
  (rm -r $REDO_SRC_PATH; exit 4)))


