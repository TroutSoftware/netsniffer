#!/bin/sh

# Ensure the environment and builds are ready
redo-ifchange envrc bootstrap/deps bootstrap/snort_install_debug debug || exit 1
. ./envrc

# 1. Define paths for clarity
SNORT_BIN="$INSTALL_DEBUG_DIR/bin/snort"
PLUGIN_PATH="$BUILD_DIR/debug/tm.so"

# 2. Build the default arguments list
# We use "$@" at the end to catch any test-specific flags you pass to the script
SNORT_ARGS="-v --warn-all --plugin-path $PLUGIN_PATH $@"

echo "Starting LLDB with: $SNORT_BIN $SNORT_ARGS"

# 3. Launch LLDB
# -o: Runs a command as soon as the target is created.
# --: Tells the 'run' command that everything following is an argument for Snort.
lldb -o "breakpoint set -E c++" \
     -o "run $SNORT_ARGS" \
     -- "$SNORT_BIN"

