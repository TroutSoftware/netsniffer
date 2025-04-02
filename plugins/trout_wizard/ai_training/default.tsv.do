. ./envrc

# $3 is the output
no_extension_file_name=${2%.tsv}
only_base_name=${no_extension_file_name#output/}
input_file=pcaps/${only_base_name}.pcap
log_file=output/${only_base_name}.log

redo-ifchange $input_file
export OUTPUT_FILE_NAME="$3"

$SNORT -c to_tsv.lua $SNORT_DAQ_INCLUDE_OPTION --plugin-path $SNORT_PLUGIN_PATH -r $input_file > $log_file

# $SNORT -c <geneericconfig> -pcap-in=$PCAP_DIR/${2%.tsv}.pcap
