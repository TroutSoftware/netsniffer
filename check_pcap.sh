#!/bin/sh
#
# check_pcap.sh: command-line tool to test a detection rule against a PCAP
#
# Expectations:
#  - HUB environment variable set to the local checkout of the “hub” project
#  - PCAPS environment variable set to the mount of PCAPS shared drive
#  - current version of netsniffer built (currently using the crutch bshell + snort.sh)

set -e

ALPINE_OS=p/alpine_build/os
DEBUG_CORE_BUILD=p/alpine_build/p/install_debug
DEBUG_BUILD=p/alpine_build/p/debug

_bwrap() {
    bwrap --tmpfs / \
        --clearenv \
        --ro-bind "$ALPINE_OS/bin" /bin \
        --ro-bind "$ALPINE_OS/etc" /etc \
        --ro-bind "$ALPINE_OS/lib" /lib \
        --ro-bind "$ALPINE_OS/sbin" /sbin \
        --bind "$ALPINE_OS/usr" /usr \
        --dir /tmp --proc proc --dev dev --dir /run \
        --bind "$DEBUG_CORE_BUILD" "/opt/netsniffer" \
        --ro-bind "$DEBUG_BUILD" "/opt/netsniffer/plugins" \
        --ro-bind $PCAPS "/PCAPS" \
        --ro-bind $HUB  "/hub" \
        --setenv LD_LIBRARY_PATH "/opt/netsniffer/lib" \
        "$@"
}

config=$1
if [ ! -e $HUB/alerts/$config ]; then echo "no such config $HUB/alerts/$config"; exit 1; fi
pcap=$(awk '$0 ~ "-- PCAP: " {print $3} ' $HUB/alerts/$config)

_bwrap /opt/netsniffer/bin/snort --warn-all \
  -r "/PCAPS/$pcap" -c "/hub/alerts/$config" -A talos

#
#
#
#
#
# $INSTALL_DEBUG_DIR/bin/snort \
#     -v \
#     --warn-all \
#     --daq-dir "$DAQ_LIB_DIR" \
#
