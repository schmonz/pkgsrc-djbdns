#!/bin/sh
MAKELIB="`head -n 1 conf-ar`"
cat warn-auto.sh
echo 'main="${1}"; shift'
echo 'rm -f "${main}"'
echo "${MAKELIB}" '"${main}" ${1+"$@"}'
echo 'ranlib "${main}"'
