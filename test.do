redo-ifchange sh3_tests.list release envrc
. ./envrc

exec >&2
go test ./...
ninja -C p/release
grep -v '^#' sh3_tests.list | sed s#^#$PD/# |  xargs go tool sh3 