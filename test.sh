#!/bin/sh

# Usage: ./test.sh module_name (e.g. ./test.sh arp_monitor)

redo-ifchange bootstrap/deps bootstrap/snort_build || exit 1
redo-ifchange deps release envrc || exit 1
. ./envrc


go tool sh3 "$PD/$@"
