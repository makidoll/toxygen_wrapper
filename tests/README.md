These are the tests taken from <https://github.com/oxij/PyTox>
forked from https://github.com/aitjcize/PyTox by Wei-Ning Huang
<aitjcize@gmail.com>. They have been converted to work with ```toxygen```.

All of the dependencies on ```toxygen``` should have been removed,
but if you copy this directory to a subdirectory of ```toxygen/toxygen```
then the tests may expand to testing some features of ```toxygen``` as well.
The tests are good examples of how to run Tox in Python.

You can run the tests by running ```tests_socks.py```.

```
usage: tests_socks.py [-h] [--proxy_host PROXY_HOST] [--proxy_port PROXY_PORT]
                      [--proxy_type {0,1,2}] [--udp_enabled {True,False}]
                      [--ipv6_enabled {False,False}]
                      [--download_nodes_list {True,False}]
                      [--nodes_json NODES_JSON]
                      [--network {old,new,local,newlocal}]
                      [--download_nodes_url DOWNLOAD_NODES_URL]
                      [--logfile LOGFILE] [--loglevel LOGLEVEL]
                      [--tcp_port TCP_PORT] [--mode MODE]
                      [--sleep {qt,gevent,time}]
                      [profile]

positional arguments:
  profile               Path to Tox profileoptional arguments:
  -h, --help            show this help message and exit
  --proxy_host PROXY_HOST, --proxy-host PROXY_HOST
                        proxy host
  --proxy_port PROXY_PORT, --proxy-port PROXY_PORT
                        proxy port
  --proxy_type {0,1,2}, --proxy-type {0,1,2}
                        proxy type 1=http, 2=socks
  --udp_enabled {True,False}
                        En/Disable udp
  --ipv6_enabled {False,False}
                        En/Disable ipv6 - default False
  --download_nodes_list {True,False}
                        Download nodes list
  --nodes_json NODES_JSON
  --network {old,new,local,newlocal}
  --download_nodes_url DOWNLOAD_NODES_URL
  --logfile LOGFILE     Filename for logging
  --loglevel LOGLEVEL   Threshold for logging (lower is more) default: 20
  --tcp_port TCP_PORT, --tcp-port TCP_PORT
  --mode MODE           Mode: 0=chat 1=chat+audio 2=chat+audio+video default:
                        0
  --sleep {qt,gevent,time}
                        Sleep method - one of qt, gevent , time
```

Look at the ```@unittest``` decorators in the code for tests that
are known to fail, or are unfinished. They will be skipped, but should
all be fixed and made to work. It has been tested with UDP and TCP proxy
(Tor). It has ***not*** been tested on Windows, and there may be some
breakage, which should be easy to fix.

Currently:
```
Ran 34 tests in 86.589s
OK (skipped=12)
```
