. ../../../envrc

in="$(dirname "$1")/../pcaps/$(basename -s .tsv "$2").pcap"
redo-ifchange $in to_tsv.lua

$BUILD_DIR/install/bin/snort -c to_tsv.lua --plugin-path "$BUILD_DIR/release/" --lua logger_file.file_name=\""$3"\" -r "$in" >&2