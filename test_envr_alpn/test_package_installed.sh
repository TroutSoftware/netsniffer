#!/bin/sh

if [ $# -gt 0 ]; then

  for package in "$@"
  do
    apt list --installed $package 2> /dev/null | grep "$package/" > /dev/null
    if [ $? -ne 0 ]; then
      echo "$package not installed" >&2
      exit 1
    fi
  done

  exit 0
fi

exit 2
