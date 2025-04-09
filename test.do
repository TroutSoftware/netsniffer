redo-ifchange sh3_tests release
cat sh3_tests | grep -v '^#' | xargs go tool sh3