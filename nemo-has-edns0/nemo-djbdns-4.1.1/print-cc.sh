#!/bin/sh
COMPILE="`head -n 1 conf-cc`"
cat warn-auto.sh
echo "exec ${COMPILE} -c" '${1+"$@"}'
