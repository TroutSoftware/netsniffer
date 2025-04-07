redo-ifchange envrc
redo-ifchange deps

if [ ! -e p/release ]; then
	redo release
fi

ninja -C p/release >&2