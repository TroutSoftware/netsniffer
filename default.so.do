# compile using 
# sort out using local h files (maybe we don’t _need_ them?)

d="$(dirname "$1")"
mkdir -p "$d"

redo-ifchange envrc configure "$(dirname $1)/build.ninja"
./configure > "$d/compile"
chmod +x "$d/compile"

cat "sources.list" | xargs ./"$d/compile" "$3"
# gen deps