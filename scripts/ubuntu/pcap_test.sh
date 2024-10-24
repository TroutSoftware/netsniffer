#!/bin/bash

#
# This file shows how snort can be launched with the snort.sh script from the command line
#

./snort.sh -v -c ../common/test-local.lua --plugin-path ../../bin --warn-all -r ../common/google_http.pcap
