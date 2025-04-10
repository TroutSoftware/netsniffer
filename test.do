redo-ifchange sh3_tests.list release envrc
. ./envrc

go test ./... >&2

ninja -C p/release >&2
cat sh3_tests.list | grep -v '^#' | sed s#^#$PD/# |  xargs go tool sh3