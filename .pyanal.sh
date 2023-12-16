#!/bin/sh

ROLE=logging

PYTHONPATH=$PWD/wrapper /var/local/bin/python3.bash `which pyanalyze` \
	tox_wrapper/tox.py tox_wrapper/tests/tests_wrapper.py \
	> .pyanal.out 2>&1

