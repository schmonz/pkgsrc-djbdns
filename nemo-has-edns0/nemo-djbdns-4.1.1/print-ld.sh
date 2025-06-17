#!/bin/sh
LOAD="`head -n 1 conf-ld`"
cat warn-auto.sh
echo 'main="${1}"; shift'
echo "exec ${LOAD} -o" '"${main}" "${main}".o ${1+"$@"} -lcdb -ldjbcal -ldjbio -ldjb'
