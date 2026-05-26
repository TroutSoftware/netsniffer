#!/bin/sh

redo-ifchange envrc debug || exit 1

. ./envrc

# Explicitly set the DAQ directory so Snort finds the modules automatically
DAQ_LIB_DIR="$INSTALL_DEBUG_DIR/lib/daq"

set -x

SNORT_LAUNCHER="$TMP_FOLDER/snort.launch.sh"

cat << EOF > "$SNORT_LAUNCHER"
# Inject the runtime flags directly into the compiler variable
# This prevents libtool from stripping them out
echo $INSTALL_DEBUG_DIR/bin/snort -v --warn-all --daq-dir "$DAQ_LIB_DIR" "$@"
LD_LIBRARY_PATH=$LD_LIBRARY_PATH_DEBUG \
$INSTALL_DEBUG_DIR/bin/snort -v --warn-all --daq-dir "$DAQ_LIB_DIR" $@


EOF

chmod +x "$SNORT_LAUNCHER"
_env_build "$SNORT_LAUNCHER"
