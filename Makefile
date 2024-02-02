PREFIX=/usr/local
PYTHON=python3.sh
PIP=pip3.sh 

prepare::
	bash .pylint.sh

check::
	PYTHONPATH=$${PWD}/src pyanalyze \
	src/tox_wrapper/tox.py src/tox_wrapper/tests/tests_wrapper.py \
	> .pyanal.out 2>&1

install::
	$(PIP) install --target $PREFIX/lib/python3.11/site-packages --upgrade .

rsync::
	bash .rsync.sh

help::
	PYTHONPATH=$${PWD}/src \
	$(PYTHON) src/tox_wrapper/tests/tests_wrapper.py --help

test::
	PYTHONPATH=$${PWD}/src \
	$(PYTHON) src/tox_wrapper/tests/tests_wrapper.py

clean::
	rm -f .[a-z]* *~ */*~ */*/*~
	rm -rf *.egg-info
