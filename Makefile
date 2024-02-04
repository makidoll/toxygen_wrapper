PREFIX=/usr/local
PYTHON=python3.sh
PIP=pip3.sh 
iTEST_TIMEOUT=60
fSOCKET_TIMEOUT=15.0

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
test_direct::
	PYTHONPATH=$${PWD}/src \
	sudo -u bin $(PYTHON) src/tox_wrapper/tests/tests_wrapper.py \
		--test_timeout=${iTEST_TIMEOUT} \
		--nodes_json=/tmp/toxygen_nodes.json \
		--udp_enabled=True  \
	     --trace_enabled=False --loglevel=10

test_proxy::
	PYTHONPATH=$${PWD}/src \
	$(PYTHON) src/tox_wrapper/tests/tests_wrapper.py \
		--test_timeout=${iTEST_TIMEOUT} \
		--proxy_host=127.0.0.1 \
		--proxy_port=9050 \
		--proxy_type=2 \
		--nodes_json=$$HOME/.config/tox/DHTnodes.json \
		--trace_enabled=False --loglevel=10

clean::
	rm -f .[a-z]* *~ */*~ */*/*~
	rm -rf *.egg-info
