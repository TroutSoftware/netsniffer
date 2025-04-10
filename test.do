redo-ifchange sh3_tests release envrc
. ./envrc

go test ./... >&2

ninja -C p/release >&2
cat sh3_tests | grep -v '^#' | sed s#^#$PD/# |  xargs go tool sh3