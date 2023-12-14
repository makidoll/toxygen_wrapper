#!/bin/sh

ROLE=logging

PYTHONPATH=$PWD/wrapper /var/local/bin/python3.bash `which pyanalyze` \
	wrapper wrapper_tests/tests_wrapper.py \
	> .pyanal.out 2>&1

