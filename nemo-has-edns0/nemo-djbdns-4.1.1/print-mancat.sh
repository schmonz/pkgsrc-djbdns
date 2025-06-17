#!/bin/sh
cat warn-auto.sh
echo 'if [ ! -f ${1} ] ; then'
echo ' echo ${1} missing'
echo ' exit 1'
echo 'fi'
echo 'exec nroff -mdoc ${1}'
