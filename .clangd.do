redo-ifchange envrc

. ./envrc

cat <<EOF
# Don't edit this file directly, edit .clangd.do instead
CompileFlags:
  Add:
    - --target=x86_64-alpine-linux-musl
    - --sysroot=$TEST_DIR_ALPN_OS

EOF
