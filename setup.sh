#!/bin/sh

# Script that initialised a new working folder

# Fail if anything fail
set -e

# Defaults:

ME="$0"
SOURCE_FOLDER="$(cd "$(dirname "$0")" && pwd)"
SOURCE_SCRIPT_FOLDER="$SOURCE_FOLDER/script_helpers"

MODE=DEBUG
TARGET=ALPINE
OUTPUT="$SOURCE_FOLDER/p"
DOWNLOAD_CACHE="$SOURCE_FOLDER/cache"

_echo_help() {
  echo "$ME --mode=[DEBUG|RELEASE] --target=[ALPINE|HOST] --output=<build_folder> --download_cache=<download_folder>" >&2
  echo "Default parameters:" >&2
  echo "$ME --mode=$MODE --target=$TARGET --output=$OUTPUT --download_cache=$DOWNLOAD_CACHE" >&2
}

# We use while-shift vs a for loop so a parameter can take multiple arguments
while [ $# -gt 0 ]; do
  case "$1" in
    --mode=*)
      MODE="${1#*=}"
      ;;
    --target=*)
      TARGET="${1#*=}"
      ;;
    --output=*)
      OUTPUT="${1#*=}"
      ;;
    --download_cache=*)
      DOWNLOAD_CACHE="${1#*=}"
      ;;
    *)
      echo "Unknown option: $1" >&2
      echo "Valid options:" >&2
      _echo_help
      exit 1
      ;;
  esac
  shift
done

# Todo: Validate arguments


mkdir -p "$OUTPUT"

cat << EOF > "$OUTPUT/setup.rc"
# This file holds the configuration for this project build folder
# Do NOT modify this file by hand, modify $ME and regenerate
MODE=$MODE
TARGET=$TARGET
DOWNLOAD_CACHE=$DOWNLOAD_CACHE
EOF

cd "$OUTPUT"
$SOURCE_FOLDER/generate.sh
echo "Change folder to \"$OUTPUT\" to use scripts"
