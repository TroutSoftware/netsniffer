redo-ifchange envrc

. ./envrc

mkdir -p $TMP_FOLDER

redo-ifchange build_scripts/ninja_configure
redo-ifchange build_scripts/daq2json
redo-ifchange build_scripts/snort_config

# Call perl to remove the first and last "[", "]" from the json given as parameter
get_middle() {
  perl -0777 -ne 'if (/^\s*\[(.*)\]\s*$/s) {print $1} else {exit 1}' "$1"
}

echo "["

get_middle $TMP_FOLDER/compile_commands.core

echo ","

get_middle $TMP_FOLDER/compile_commands.daq

echo ","

get_middle $TMP_FOLDER/compile_commands.plugins

echo "]"






