redo-ifchange envrc

. ./envrc


mkdir -p $TMP_FOLDER

redo-ifchange build_scripts/ninja_configure
redo-ifchange build_scripts/daq2json
redo-ifchange build_scripts/snort_config

#todo: merge all output from the tmp folder here...




