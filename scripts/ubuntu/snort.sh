#!/bin/bash

# Helper script to launch snort without installing it

LD_LIBRARY_PATH="../../lib" ../../bin/snort --daq-dir ../../lib/daq $@
