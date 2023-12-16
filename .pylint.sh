#!/bin/sh

EXE=/var/local/bin/pydev_pylint.bash
ROLE=logging

$EXE --recursive y --verbose --py-version 3.11 \
  --output-format colorized --rcfile .pylint.rc \
  -E -f text tox_wrapper/*py tox_wrapper/tests/*py  > .pylint.err
retval=$?

$EXE --recursive y --verbose --py-version 3.11 \
  --output-format colorized --rcfile .pylint.rc \
  tox_wrapper/*py tox_wrapper/tests/*py > .pylint.out

sed -e "/Module 'os' has no/d" \
    -e "/Undefined variable 'app'/d" \
    -e '/tests\//d' \
    -e "/Instance of 'Curl' has no /d" \
    -e "/No name 'path' in module 'os' /d" \
    -e "/ in module 'os'/d" \
    -e "/.bak\//d" \
	-i .pylint.err .pylint.out
