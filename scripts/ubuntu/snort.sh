#!/bin/bash

# Helper script to launch snort without installing it

LD_LIBRARY_PATH="../../lib" ../../bin/snort --plugin-path ../../bin --daq-dir ../../lib/daq $@
