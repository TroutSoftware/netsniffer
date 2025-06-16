redo-ifchange deps sh3_tests.list release envrc
. ./envrc

go test ./...
grep -v '^#' sh3_tests.list | sed s#^#$PD/# |  xargs go tool sh3 $*
