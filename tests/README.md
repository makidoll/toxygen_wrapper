]
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
                        tcp port
  --mode MODE           Mode: 0=chat 1=chat+audio 2=chat+audio+video default:
                        0
  --sleep {qt,gevent,time}
                        Sleep method - one of qt, gevent , time
