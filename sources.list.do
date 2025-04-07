# redo p/release/sources.list
#
# => find tm/plugins.rc
# => for each module in tm, compile using the compile folder

redo-ifchange envrc

. ./envrc
echo "$PD/snort_plugins.cc" > "$3"

redo-ifchange plugins.list
for m in $(cat plugins.list); do
	cat "$PD/$m/files.list" | sed s#^#"$PD/$m/"#
	printf "\n"
done >> "$3"