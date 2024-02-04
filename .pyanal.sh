#!/bin/sh

ROLE=logging

PYTHONPATH=$PWD/src /var/local/bin/python3.bash `which pyanalyze` \
	src/tox_wrapper/tox.py src/tox_wrapper/tests/tests_wrapper.py \
	> .pyanal.out 2>&1

