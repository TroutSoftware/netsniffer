#!/bin/bash

@echo "This script installs the dependencies needed to run snort on systems that don't have the tool chain to build it"
sudo apt install libhwloc15 libdumbnet1 libluajit-5.1-2 libpcap0.8t64 libpcre3
