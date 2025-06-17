#!/bin/sh
DATE="`head -n 1 DATE`"
VERSION="`head -n 1 VERSION`"
PREFIX="`head -n 1 conf-prefix`"
cat warn-auto.sh
echo 'COMMAND=`basename ${0}`'
echo 'usage() { echo "usage: ${COMMAND} filename" ; exit 1 ; }'
echo 'err() { echo "${COMMAND}: error: ${*}" ; exit 2 ; }'
echo 'if [ -z "${1}" ] ; then'
echo ' usage'
echo 'fi'
echo 'if [ ! -f ${1} ] ; then'
echo ' err "${1} not found"'
echo 'fi'
echo 'exec cat ${1} | sed "s}@PREFIX@}'${PREFIX}'}g" | sed "s}@DATE@}'${DATE}'}g" | sed "s}@VERSION@}'${VERSION}'}g"'
