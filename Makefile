PREFIX=/usr/local
PYTHON_EXE_MSYS=${PREFIX}/bin/python3.sh
PIP_EXE_MSYS=${PREFIX}/bin/pip3.sh
 
iTEST_TIMEOUT=60
fSOCKET_TIMEOUT=15.0
PYTHON_MINOR=`python3 --version 2>&1 | sed -e 's@^.* @@' -e 's@\.[0-9]*$$@@'`

prepare::
	bash .pylint.sh

check::
	PYTHONPATH=$${PWD}/src pyanalyze \
	src/toxygen_wrapper/tox.py src/toxygen_wrapper/tests/tests_wrapper.py \
	> .pyanal.out 2>&1

install::
	${PIP_EXE_MSYS} --python ${PYTHON_EXE_MSYS} install \
		--target ${PREFIX}/lib/python${PYTHON_MINOR}/site-packages/ \
		--upgrade .

rsync::
	bash .rsync.sh

help::
	PYTHONPATH=$${PWD}/src \
	$(PYTHON) src/toxygen_wrapper/tests/tests_wrapper.py --help

test::
test_direct::
	cp -p ${HOME}/.config/tox/DHTnodes.json /tmp/toxygen_nodes.json
	PYTHONPATH=$${PWD}/src \
	sudo -u bin $(PYTHON_EXE_MSYS) src/toxygen_wrapper/tests/tests_wrapper.py \
		--socket_timeout=10.0 \
		--test_timeout=${iTEST_TIMEOUT} \
		--nodes_json=/tmp/toxygen_nodes.json \
		--udp_enabled=True  \
	     --trace_enabled=False --loglevel=10

test_proxy::
	PYTHONPATH=$${PWD}/src \
	${PYTHON_EXE_MSYS} src/toxygen_wrapper/tests/tests_wrapper.py \
		--socket_timeout=15.0 \
		--test_timeout=${iTEST_TIMEOUT} \
		--proxy_host=127.0.0.1 \
		--proxy_port=9050 \
		--proxy_type=2 \
		--nodes_json=$$HOME/.config/tox/DHTnodes.json \
		--trace_enabled=False --loglevel=10

clean::
	rm -f .[a-z]*~ *~ */*~ */*/*~
	rm -rf *.egg-info
