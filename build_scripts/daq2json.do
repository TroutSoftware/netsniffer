redo-ifchange ../envrc libdaq_vars.rc libdaq_config

. ../envrc
. $TMP_FOLDER/libdaq_vars.rc

OUTPUT="$TMP_FOLDER/compile_commands.daq"

echo "[" > "$OUTPUT"

PREPEND_COMMA=false

find $LIBDAQ_SRC_DIR -type f -name '*.c' -print0 |
while IFS= read -r -d '' FILE; do

  if $PREPEND_COMMA; then
    echo "," >> "$OUTPUT"
  fi

  PREPEND_COMMA=true

  FILE_DIR=$(dirname $FILE)

  cat <<EOF >> "$OUTPUT"
  {
      "directory": "$FILE_DIR",
      "command": "$CC $CFLAGS -I. -I$FILE_DIR -I.. -I$LIBDAQ_SRC_DIR/api -c $FILE"
      "file": "$FILE"
  }
EOF

done

echo "]" >> "$OUTPUT"

redo-ifchange "$OUTPUT"

