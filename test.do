redo-ifchange sh3_tests.list release envrc
. ./envrc

exec >&2
go test ./...
ninja -C p/release
cat sh3_tests.list | grep -v '^#' | sed s#^#$PD/# |  xargs go tool sh3 