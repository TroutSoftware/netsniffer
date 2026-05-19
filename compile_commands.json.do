redo-ifchange envrc

. ./envrc

redo-ifchange .clangd

mkdir -p $TMP_FOLDER

redo-ifchange build_scripts/daq2json
redo-ifchange build_scripts/snort_config

# Call perl to remove the first and last "[", "]" from the json given as parameter
get_middle() {
  perl -0777 -ne '
      if (/^\s*\[(.*)\]\s*$/s) {
          print $1;
      } else {
          warn "ERROR: compile_commands does not match .json [ ... ] pattern\n";
          exit 1;
      }
  ' "$1"
}

# Do folder substitution so it fits the host structure
map_paths() {
  perl -pe "s|\Q$BASE_DIR/p\E|$TEST_ENV_BUILD_DIR|g;"
}

echo "["

get_middle $TMP_FOLDER/compile_commands.core | map_paths

echo ","

get_middle $TMP_FOLDER/compile_commands.daq | map_paths

echo "]"






