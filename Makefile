PYTHON=python3

prepare::
	bash .pylint.sh

check::
	PYTHONPATH=${PWD} pyanalyze \
	tox_wrapper/tox.py tox_wrapper/tests/tests_wrapper.py \
	> .pyanal.out 2>&1

install::
	$(PYTHON) setup.py install

test;:
	$(PYTHON) tox_wrapper/tests/tests_wrapper.py

clean::
	rm -f *~ */*~ */*/*~
	rm -rf *.egg-info
