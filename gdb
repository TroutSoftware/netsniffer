#!/bin/sh

usage=<<EOF
Usage:
  gdb MODULE TEST
EOF

redo-ifchange debug
go tool sh3 -gdb -debug -r $2 $1