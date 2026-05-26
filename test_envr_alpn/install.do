exec >install.log

redo-ifchange envrc fetch packages-alpine build-lib.rc config-host alpine_modified

. ./envrc
. ./build-lib.rc

# Make sure dir structure is created
[ -d $TEST_DIR_BUILD ] || mkdir -p $TEST_DIR_BUILD

# properly handle resolv changes
redo-ifchange /etc/resolv.conf
install -D -m 644 /etc/resolv.conf $TEST_DIR_ALPN_OS/etc/resolv.conf

cat packages-alpine| grep -v "^#" | xargs unshare --map-auto --map-root chroot $TEST_DIR_ALPN_OS apk add # > install.log


echo INSTALL RAN >&2
