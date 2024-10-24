This is the readme.txt for our local snort builds.

The ubuntu folder contains the following scripts:
------------------------------------------------------------------------
install-runtime-dependencies.sh
 - This file will install the runtime dependencies that snort requires to run and which are not part of the build

snort.sh
 - This is a wrapper for the snort executable that sets up a few things so snort can be run without being installed on the system

pcap_test.sh
 - Shows how snort.sh can be called to run snort on a pcap file
------------------------------------------------------------------------

Some test files required by the pcap_test.sh script can be found in the common folder
------------------------------------------------------------------------
google_http.pcap
 - Sample pcap file

test-local.lua
 - Sample lua script file

test-local.rules
 - Sample rules file used by the test-local.lua script file
------------------------------------------------------------------------

The snort binaries can be found in: ../bin

Additional lua scripts from the snort dist can be found in: ../etc/snort
