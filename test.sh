#!/bin/sh

# Usage: ./test.sh module_name (e.g. ./test.sh arp_monitor)

redo-ifchange envrc release || exit 1

. ./envrc


go tool sh3 "$PD/$@"
