redo-ifchange deps sh3_tests.list release envrc || exit -1
. ./envrc

go test ./...
grep -v '^#' sh3_tests.list | sed s#^#$PD/# |  xargs go tool sh3 $*
