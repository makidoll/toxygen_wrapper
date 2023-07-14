# -*- mode: python; indent-tabs-mode: nil; py-indent-offset: 4; coding: utf-8 -*-

import argparse
import contextlib
import inspect
import json
import logging
import os
import re
import select
import shutil
import socket
import sys
import time
import traceback
import unittest
from ctypes import *
from random import Random
import functools

random = Random()

try:
    import coloredlogs
    if 'COLOREDLOGS_LEVEL_STYLES' not in os.environ:
        os.environ['COLOREDLOGS_LEVEL_STYLES'] = 'spam=22;debug=28;verbose=34;notice=220;warning=202;success=118,bold;error=124;critical=background=red'
    # https://pypi.org/project/coloredlogs/
except ImportError as e:
    coloredlogs = False
try:
    import stem
except ImportError as e:
    stem = False
try:
    import nmap
except ImportError as e:
    nmap = False

import wrapper
from wrapper.toxcore_enums_and_consts import TOX_CONNECTION, TOX_USER_STATUS

from wrapper_tests.support_http import bAreWeConnected
from wrapper_tests.support_onions import (is_valid_fingerprint,
                                          lIntroductionPoints,
                                          oGetStemController,
                                          sMapaddressResolv, sTorResolve)

try:
    from user_data.settings import get_user_config_path
except ImportError:
    get_user_config_path = None

# LOG=util.log
global LOG
LOG = logging.getLogger()

def LOG_ERROR(l): print('ERRORc: '+l)
def LOG_WARN(l):  print('WARNc: ' +l)
def LOG_INFO(l):  print('INFOc: ' +l)
def LOG_DEBUG(l): print('DEBUGc: '+l)
def LOG_TRACE(l): pass # print('TRACE+ '+l)

try:
    from trepan.api import debug
    from trepan.interfaces import server as Mserver
except:
#    print('trepan3 TCP server NOT available.')
    pass
else:
#    print('trepan3 TCP server available.')
    def trepan_handler(num=None, f=None):
        connection_opts={'IO': 'TCP', 'PORT': 6666}
        intf = Mserver.ServerInterface(connection_opts=connection_opts)
        dbg_opts = { 'interface': intf }
        print(f'Starting TCP server listening on port 6666.')
        debug(dbg_opts=dbg_opts)
        return

# self._audio_thread.isAlive
iTHREAD_TIMEOUT = 1
iTHREAD_SLEEP = 1
iTHREAD_JOINS = 8
iNODES = 6

lToxSamplerates = [8000, 12000, 16000, 24000, 48000]
lToxSampleratesK = [8, 12, 16, 24, 48]
lBOOLEANS = [
        'local_discovery_enabled',
        'udp_enabled',
        'ipv6_enabled',
        'trace_enabled',
        'compact_mode',
        'allow_inline',
        'notifications',
        'sound_notifications',
        'calls_sound',
        'hole_punching_enabled',
        'dht_announcements_enabled',
        'save_history',
        'download_nodes_list'
        'core_logging',
        ]

sDIR = os.environ.get('TMPDIR', '/tmp')
sTOX_VERSION = "1000002018"
bHAVE_NMAP = shutil.which('nmap')
bHAVE_JQ = shutil.which('jq')
bHAVE_BASH = shutil.which('bash')
bHAVE_TORR = shutil.which('tor-resolve')

lDEAD_BS = [
    # Failed to resolve "tox3.plastiras.org"
    "tox3.plastiras.org",
    'tox.kolka.tech',
    # IPs that do not reverse resolve
    '49.12.229.145',
    "46.101.197.175",
    '114.35.245.150',
    '172.93.52.70',
    '195.123.208.139',
    '205.185.115.131',
    # IPs that do not rreverse resolve
    'yggnode.cf', '188.225.9.167',
    '85-143-221-42.simplecloud.ru', '85.143.221.42',
    # IPs that do not ping
    '104.244.74.69', 'tox.plastiras.org',
    '195.123.208.139',
    'gt.sot-te.ch', '32.226.5.82',
    # suspicious IPs
    'tox.abilinski.com', '172.103.164.250', '172.103.164.250.tpia.cipherkey.com',
    ]


def assert_main_thread():
    from PyQt5 import QtCore, QtWidgets
    from qtpy.QtWidgets import QApplication

    # this "instance" method is very useful!
    app_thread = QtWidgets.QApplication.instance().thread()
    curr_thread = QtCore.QThread.currentThread()
    if app_thread != curr_thread:
        raise RuntimeError('attempt to call MainWindow.append_message from non-app thread')

@contextlib.contextmanager
def ignoreStdout():
    devnull = os.open(os.devnull, os.O_WRONLY)
    old_stdout = os.dup(1)
    sys.stdout.flush()
    os.dup2(devnull, 1)
    os.close(devnull)
    try:
        yield
    finally:
        os.dup2(old_stdout, 1)
        os.close(old_stdout)

@contextlib.contextmanager
def ignoreStderr():
    devnull = os.open(os.devnull, os.O_WRONLY)
    old_stderr = os.dup(2)
    sys.stderr.flush()
    os.dup2(devnull, 2)
    os.close(devnull)
    try:
        yield
    finally:
        os.dup2(old_stderr, 2)
        os.close(old_stderr)

def clean_booleans(oArgs):
    for key in lBOOLEANS:
        if not hasattr(oArgs, key): continue
        val = getattr(oArgs, key)
        if type(val) == bool: continue
        if val in ['False', 'false', '0']:
            setattr(oArgs, key, False)
        else:
            setattr(oArgs, key, True)

def on_log(iTox, level, filename, line, func, message, *data):
    # LOG.debug(repr((level, filename, line, func, message,)))
    tox_log_cb(level, filename, line, func, message)

def tox_log_cb(level, filename, line, func, message, *args):
    """
    * @param level The severity of the log message.
    * @param filename The source file from which the message originated.
    * @param line The source line from which the message originated.
    * @param func The function from which the message originated.
    * @param message The log message.
    * @param user_data The user data pointer passed to tox_new in options.
    """
    if type(func) == bytes:
        func = str(func, 'utf-8')
        message = str(message, 'UTF-8')
        filename = str(filename, 'UTF-8')

        if filename == 'network.c':
            if line == 660: return
                # root WARNING 3network.c#944:b'send_packet'attempted to send message with network family 10 (probably IPv6) on IPv4 socket
            if line == 944: return
            i = message.find('07 = GET_NODES')
            if i > 0:
                return
        if filename == 'TCP_common.c': return

        i = message.find(' | ')
        if i > 0:
            message = message[:i]
        # message = filename +'#' +str(line) +':'+func +' '+message

        name = 'core'
        # old level is meaningless
        level = 10 # LOG.level

        # LOG._log(LOG.level, f"{level}: {message}", list())

        i = message.find('(0: OK)')
        if i > 0:
            level = 10 # LOG.debug
        else:
            i = message.find('(1: ')
            if i > 0:
                level = 30 # LOG.warn
            else:
                level = 20 # LOG.info

        o = LOG.makeRecord(filename, level, func, line, message, list(), None)
        # LOG.handle(o)
        LOG_TRACE(f"{level}: {func}{line} {message}")
        return

    elif level == 1:
        LOG.critical(f"{level}: {message}")
    elif level == 2:
        LOG.error(f"{level}: {message}")
    elif level == 3:
        LOG.warn(f"{level}: {message}")
    elif level == 4:
        LOG.info(f"{level}: {message}")
    elif level == 5:
        LOG.debug(f"{level}: {message}")
    else:
        LOG_TRACE(f"{level}: {message}")

def vAddLoggerCallback(tox_options, callback=None):
    if callback is None:
        wrapper.tox.Tox.libtoxcore.tox_options_set_log_callback(
            tox_options._options_pointer,
            POINTER(None)())
        tox_options.self_logger_cb = None
        return

    c_callback = CFUNCTYPE(None, c_void_p, c_int, c_char_p, c_int, c_char_p, c_char_p, c_void_p)
    tox_options.self_logger_cb = c_callback(callback)
    wrapper.tox.Tox.libtoxcore.tox_options_set_log_callback(
        tox_options._options_pointer,
        tox_options.self_logger_cb)

def get_video_indexes():
    # Linux
    return [str(l[5:]) for l in os.listdir('/dev/') if l.startswith('video')]

def get_audio():
    with ignoreStderr():
        import pyaudio
    oPyA = pyaudio.PyAudio()

    input_devices = output_devices = 0
    for i in range(oPyA.get_device_count()):
        device = oPyA.get_device_info_by_index(i)
        if device["maxInputChannels"]:
            input_devices += 1
        if device["maxOutputChannels"]:
            output_devices += 1
    # {'index': 21, 'structVersion': 2, 'name': 'default', 'hostApi': 0, 'maxInputChannels': 64, 'maxOutputChannels': 64, 'defaultLowInputLatency': 0.008707482993197279, 'defaultLowOutputLatency': 0.008707482993197279, 'defaultHighInputLatency': 0.034829931972789115, 'defaultHighOutputLatency': 0.034829931972789115, 'defaultSampleRate': 44100.0}
    audio = {'input': oPyA.get_default_input_device_info()['index'] if input_devices else -1,
             'output': oPyA.get_default_output_device_info()['index'] if output_devices else -1,
             'enabled': input_devices and output_devices}
    return audio

def oMainArgparser(_=None, iMode=0):
    # 'Mode: 0=chat 1=chat+audio 2=chat+audio+video default: 0'
    if not os.path.exists('/proc/sys/net/ipv6'):
        bIpV6 = 'False'
    else:
        bIpV6 = 'True'
    lIpV6Choices=[bIpV6, 'False']

    sNodesJson = os.path.join(os.environ['HOME'], '.config', 'tox', 'DHTnodes.json')
    if not os.path.exists(sNodesJson): sNodesJson = ''

    logfile = os.path.join(os.environ.get('TMPDIR', '/tmp'), 'toxygen.log')
    if not os.path.exists(sNodesJson): logfile = ''

    parser = argparse.ArgumentParser(add_help=True)
    parser.add_argument('--proxy_host', '--proxy-host', type=str,
                        # oddball - we want to use '' as a setting
                        default='0.0.0.0',
                        help='proxy host')
    parser.add_argument('--proxy_port', '--proxy-port', default=0, type=int,
                        help='proxy port')
    parser.add_argument('--proxy_type', '--proxy-type', default=0, type=int,
                        choices=[0,1,2],
                        help='proxy type 1=http, 2=socks')
    parser.add_argument('--tcp_port', '--tcp-port', default=0, type=int,
                        help='tcp port')
    parser.add_argument('--udp_enabled', type=str, default='True',
                        choices=['True', 'False'],
                        help='En/Disable udp')
    parser.add_argument('--ipv6_enabled', type=str, default=bIpV6,
                        choices=lIpV6Choices,
                        help=f"En/Disable ipv6 - default  {bIpV6}")
    parser.add_argument('--trace_enabled',type=str,
                        default='True' if os.environ.get('DEBUG') else 'False',
                        choices=['True','False'],
                        help='Debugging from toxcore logger_trace or env DEBUG=1')
    parser.add_argument('--download_nodes_list', type=str, default='False',
                        choices=['True', 'False'],
                        help='Download nodes list')
    parser.add_argument('--nodes_json', type=str,
                        default=sNodesJson)
    parser.add_argument('--network', type=str,
                        choices=['main', 'local'],
                        default='main')
    parser.add_argument('--download_nodes_url', type=str,
                        default='https://nodes.tox.chat/json')
    parser.add_argument('--logfile', default=logfile,
                        help='Filename for logging - start with + for stdout too')
    parser.add_argument('--loglevel', default=logging.INFO, type=int,
                        # choices=[logging.info,logging.trace,logging.debug,logging.error]
                        help='Threshold for logging (lower is more) default: 20')
    parser.add_argument('--mode', type=int, default=iMode,
                        choices=[0,1,2],
                        help='Mode: 0=chat 1=chat+audio 2=chat+audio+video default: 0')
    parser.add_argument('--hole_punching_enabled',type=str,
                        default='False', choices=['True','False'],
                        help='En/Enable hole punching')
    parser.add_argument('--dht_announcements_enabled',type=str,
                        default='True', choices=['True','False'],
                        help='En/Disable DHT announcements')
    return parser

def vSetupLogging(oArgs):
    global LOG
    logging._defaultFormatter = logging.Formatter(datefmt='%m-%d %H:%M:%S')
    logging._defaultFormatter.default_time_format = '%m-%d %H:%M:%S'
    logging._defaultFormatter.default_msec_format = ''

    add = None
    kwargs = dict(level=oArgs.loglevel,
                  format='%(levelname)-8s %(message)s')
    if oArgs.logfile:
        add = oArgs.logfile.startswith('+')
        sub = oArgs.logfile.startswith('-')
        if add or sub:
            oArgs.logfile = oArgs.logfile[1:]
        kwargs['filename'] = oArgs.logfile

    if coloredlogs:
        # https://pypi.org/project/coloredlogs/
        aKw = dict(level=oArgs.loglevel,
                   logger=LOG,
                   stream=sys.stdout,
                   fmt='%(name)s %(levelname)s %(message)s'
                   )
        coloredlogs.install(**aKw)
        if oArgs.logfile:
            oHandler = logging.FileHandler(oArgs.logfile)
            LOG.addHandler(oHandler)
    else:
        logging.basicConfig(**kwargs)
        if add:
            oHandler = logging.StreamHandler(sys.stdout)
            LOG.addHandler(oHandler)

    LOG.info(f"Setting loglevel to {oArgs.loglevel!s}")


def setup_logging(oArgs):
    global LOG
    if coloredlogs:
        aKw = dict(level=oArgs.loglevel,
                   logger=LOG,
                   fmt='%(name)s %(levelname)s %(message)s')
        if oArgs.logfile:
            oFd = open(oArgs.logfile, 'wt')
            setattr(oArgs, 'log_oFd', oFd)
            aKw['stream'] = oFd
        coloredlogs.install(**aKw)
        if oArgs.logfile:
            oHandler = logging.StreamHandler(stream=sys.stdout)
            LOG.addHandler(oHandler)
    else:
        aKw = dict(level=oArgs.loglevel,
                   format='%(name)s %(levelname)-4s %(message)s')
        if oArgs.logfile:
            aKw['filename'] = oArgs.logfile
        logging.basicConfig(**aKw)

    logging._defaultFormatter = logging.Formatter(datefmt='%m-%d %H:%M:%S')
    logging._defaultFormatter.default_time_format = '%m-%d %H:%M:%S'
    logging._defaultFormatter.default_msec_format = ''

    LOG.setLevel(oArgs.loglevel)
#    LOG.trace = lambda l: LOG.log(0, repr(l))
    LOG.info(f"Setting loglevel to {oArgs.loglevel!s}")

def signal_handler(num, f):
    from trepan.api import debug
    from trepan.interfaces import server as Mserver
    connection_opts={'IO': 'TCP', 'PORT': 6666}
    intf = Mserver.ServerInterface(connection_opts=connection_opts)
    dbg_opts = {'interface': intf}
    LOG.info('Starting TCP server listening on port 6666.')
    debug(dbg_opts=dbg_opts)
    return

def merge_args_into_settings(args, settings):
    if args:
        if not hasattr(args, 'audio'):
            LOG.warn('No audio ' +repr(args))
        settings['audio'] = getattr(args, 'audio')
        if not hasattr(args, 'video'):
            LOG.warn('No video ' +repr(args))
        settings['video'] = getattr(args, 'video')
        for key in settings.keys():
            # proxy_type proxy_port proxy_host
            not_key = 'not_' +key
            if hasattr(args, key):
                val = getattr(args, key)
                if type(val) == bytes:
                    # proxy_host - ascii?
                    # filenames - ascii?
                    val = str(val, 'UTF-8')
                settings[key] = val
            elif hasattr(args, not_key):
                val = not getattr(args, not_key)
                settings[key] = val
    clean_settings(settings)
    return

def clean_settings(self):
    # failsafe to ensure C tox is bytes and Py settings is str

    # overrides
    self['mirror_mode'] = False
    # REQUIRED!!
    if not os.path.exists('/proc/sys/net/ipv6'):
        LOG.warn('Disabling IPV6 because /proc/sys/net/ipv6 does not exist')
        self['ipv6_enabled'] = False

    if 'proxy_type' in self and self['proxy_type'] == 0:
        self['proxy_host'] = ''
        self['proxy_port'] = 0

    if 'proxy_type' in self and self['proxy_type'] != 0 and \
        'proxy_host' in self and self['proxy_host'] != '' and \
        'proxy_port' in self and self['proxy_port'] != 0:
        if 'udp_enabled' in self and self['udp_enabled']:
            # We don't currently support UDP over proxy.
            LOG.info("UDP enabled and proxy set: disabling UDP")
        self['udp_enabled'] = False
        if 'local_discovery_enabled' in self and self['local_discovery_enabled']:
            LOG.info("local_discovery_enabled enabled and proxy set: disabling local_discovery_enabled")
        self['local_discovery_enabled'] = False
        if 'dht_announcements_enabled' in self and self['dht_announcements_enabled']:
            LOG.info("dht_announcements_enabled enabled and proxy set: disabling dht_announcements_enabled")
        self['dht_announcements_enabled'] = False

    if 'auto_accept_path' in self and \
       type(self['auto_accept_path']) == bytes:
        self['auto_accept_path'] = str(self['auto_accept_path'], 'UTF-8')

    LOG.debug("Cleaned settings")

def lSdSamplerates(iDev):
    try:
        import sounddevice as sd
    except ImportError:
        return []
    samplerates = (32000, 44100, 48000, 96000, )
    device = iDev
    supported_samplerates = []
    for fs in samplerates:
        try:
            sd.check_output_settings(device=device, samplerate=fs)
        except Exception as e:
            # LOG.debug(f"Sample rate not supported {fs}" +' '+str(e))
            pass
        else:
            supported_samplerates.append(fs)
    return supported_samplerates

def _get_nodes_path(oArgs=None):
    if oArgs and oArgs.nodes_json and os.path.isfile(oArgs.nodes_json):
        LOG.debug("_get_nodes_path: " +oArgs.nodes_json)
        default = oArgs.nodes_json
    elif get_user_config_path:
        default = os.path.join(get_user_config_path(), 'toxygen_nodes.json')
    else:
        # Windwoes
        default = os.path.join(os.getenv('HOME'), '.config', 'tox', 'toxygen_nodes.json')
    LOG.debug("_get_nodes_path: " +default)
    return default

DEFAULT_NODES_COUNT = 8

global aNODES
aNODES = {}


# @functools.lru_cache(maxsize=12) TypeError: unhashable type: 'Namespace'
def generate_nodes(oArgs=None,
                   nodes_count=DEFAULT_NODES_COUNT,
                   ipv='ipv4',
                   udp_not_tcp=True):
    global aNODES
    sKey = ipv
    sKey += ',0' if udp_not_tcp else ',1'
    if sKey in aNODES and aNODES[sKey]:
        return aNODES[sKey]
    sFile = _get_nodes_path(oArgs=oArgs)
    assert os.path.exists(sFile), sFile
    lNodes = generate_nodes_from_file(sFile,
                                      nodes_count=nodes_count,
                                      ipv=ipv, udp_not_tcp=udp_not_tcp)
    assert lNodes
    aNODES[sKey] = lNodes
    return aNODES[sKey]

aNODES_CACHE = {}
def generate_nodes_from_file(sFile,
                             nodes_count=DEFAULT_NODES_COUNT,
                             ipv='ipv4',
                             udp_not_tcp=True,
                             ):
    """https://github.com/TokTok/c-toxcore/issues/469
I had a conversation with @irungentoo on IRC about whether we really need to call tox_bootstrap() when having UDP disabled and why. The answer is yes, because in addition to TCP relays (tox_add_tcp_relay()), toxcore also needs to know addresses of UDP onion nodes in order to work correctly. The DHT, however, is not used when UDP is disabled. tox_bootstrap() function resolves the address passed to it as argument and calls onion_add_bs_node_path() and DHT_bootstrap() functions. Although calling DHT_bootstrap() is not really necessary as DHT is not used, we still need to resolve the address of the DHT node in order to populate the onion routes with onion_add_bs_node_path() call.
"""
    global aNODES_CACHE

    key = ipv
    key += ',0' if udp_not_tcp else ',1'
    if key in aNODES_CACHE:
        sorted_nodes =  aNODES_CACHE[key]
    else:
        if not os.path.exists(sFile):
            LOG.error("generate_nodes_from_file file not found " +sFile)
            return []
        try:
            with open(sFile, 'rt') as fl:
                json_nodes = json.loads(fl.read())['nodes']
        except Exception as e:
            LOG.error(f"generate_nodes_from_file error {sFile}\n{e}")
            return []
        else:
            LOG.debug("generate_nodes_from_file " +sFile)

        if udp_not_tcp:
            nodes = [(node[ipv], node['port'], node['public_key'],) for
                     node in json_nodes if node[ipv] != 'NONE' \
                          and node["status_udp"] in [True, "true"]
                     ]
        else:
            nodes = []
            elts = [(node[ipv], node['tcp_ports'], node['public_key'],) \
                    for node in json_nodes if node[ipv] != 'NONE' \
                        and node["status_tcp"] in [True, "true"]
                    ]
            for (ipv, ports, public_key,) in elts:
                for port in ports:
                    nodes += [(ipv, port, public_key)]
        if not nodes:
            LOG.warn(f'empty generate_nodes from {sFile} {json_nodes!r}')
            return []
        sorted_nodes = nodes
        aNODES_CACHE[key] = sorted_nodes

    random.shuffle(sorted_nodes)
    if nodes_count is not None and len(sorted_nodes) > nodes_count:
        sorted_nodes = sorted_nodes[-nodes_count:]
    LOG.debug(f"generate_nodes_from_file {sFile} len={len(sorted_nodes)}")
    return sorted_nodes

def tox_bootstrapd_port():
    port = 33446
    sFile = '/etc/tox-bootstrapd.conf'
    if os.path.exists(sFile):
        with open(sFile, 'rt') as oFd:
            for line in  oFd.readlines():
                if line.startswith('port = '):
                    port = int(line[7:])
    return port

def bootstrap_local(elts, lToxes, oArgs=None):
    if os.path.exists('/run/tox-bootstrapd/tox-bootstrapd.pid'):
        LOG.debug('/run/tox-bootstrapd/tox-bootstrapd.pid')
        iRet = True
    else:
        iRet = os.system("netstat -nle4|grep -q :33")
        if iRet > 0:
            LOG.warn(f'bootstraping local No local DHT running')
    LOG.info(f'bootstraping local')
    return bootstrap_udp(elts, lToxes, oArgs)

def lDNSClean(l):
    global lDEAD_BS
    # list(set(l).difference(set(lDEAD_BS)))
    return [elt for elt in l if elt not in lDEAD_BS]

def lExitExcluder(oArgs, iPort=9051):
    """
    https://raw.githubusercontent.com/nusenu/noContactInfo_Exit_Excluder/main/exclude_noContactInfo_Exits.py
    """
    if not stem:
        LOG.warn('please install the stem Python package')
        return ''
    LOG.debug('lExcludeExitNodes')

    try:
        controller = oGetStemController(log_level=10)
        # generator
        relays = controller.get_server_descriptors()
    except Exception as e:
        LOG.error(f'Failed to get relay descriptors {e}')
        return None

    if controller.is_set('ExcludeExitNodes'):
        LOG.info('ExcludeExitNodes is in use already.')
        return None

    exit_excludelist=[]
    LOG.debug("Excluded exit relays:")
    for relay in relays:
        if relay.exit_policy.is_exiting_allowed() and not relay.contact:
            if is_valid_fingerprint(relay.fingerprint):
                exit_excludelist.append(relay.fingerprint)
                LOG.debug("https://metrics.torproject.org/rs.html#details/%s" % relay.fingerprint)
            else:
                LOG.warn('Invalid Fingerprint: %s' % relay.fingerprint)

    try:
        controller.set_conf('ExcludeExitNodes', exit_excludelist)
        LOG.info('Excluded a total of %s exit relays without ContactInfo from the exit position.' % len(exit_excludelist))
    except Exception as e:
        LOG.exception('ExcludeExitNodes ' +str(e))
    return exit_excludelist

aHOSTS = {}
@functools.lru_cache(maxsize=20)
def sDNSLookup(host):
    global aHOSTS
    ipv = 0
    if host in lDEAD_BS:
#        LOG.warn(f"address skipped because in lDEAD_BS {host}")
        return ''
    if host in aHOSTS:
        return aHOSTS[host]

    try:
        s = host.replace('.','')
        int(s)
        ipv = 4
    except:
        try:
            s = host.replace(':','')
            int(s)
            ipv = 6
        except: pass

    if ipv > 0:
#        LOG.debug(f"v={ipv} IP address {host}")
        return host

    LOG.debug(f"sDNSLookup {host}")
    ip = ''
    if host.endswith('.tox') or host.endswith('.onion'):
        if False and stem:
            ip = sMapaddressResolv(host)
            if ip: return ip

        ip = sTorResolve(host)
        if ip: return ip

        if not bHAVE_TORR:
            LOG.warn(f"onion address skipped because no tor-resolve {host}")
            return ''
        try:
            sout = f"/tmp/TR{os.getpid()}.log"
            i = os.system(f"tor-resolve -4 {host} > {sout}")
            if not i:
                LOG.warn(f"onion address skipped because tor-resolve on {host}")
                return ''
            ip = open(sout, 'rt').read()
            if ip.endswith('failed.'):
                LOG.warn(f"onion address skipped because tor-resolve failed on {host}")
                return ''
            LOG.debug(f"onion address tor-resolve {ip} on {host}")
            return ip
        except:
            pass
    else:
        try:
            ip = socket.gethostbyname(host)
            LOG.debug(f"host={host} gethostbyname IP address {ip}")
            if ip:
                aHOSTS[host] = ip
                return ip
            # drop through
        except:
            # drop through
            pass

    if ip == '':
        try:
            sout = f"/tmp/TR{os.getpid()}.log"
            i = os.system(f"dig {host} +timeout=15|grep ^{host}|sed -e 's/.* //'> {sout}")
            if not i:
                LOG.warn(f"address skipped because dig failed on {host}")
                return ''
            ip = open(sout, 'rt').read().strip()
            LOG.debug(f"address dig {ip} on {host}")
            aHOSTS[host] = ip
            return ip
        except:
            ip = host
    LOG.debug(f'sDNSLookup {host} -> {ip}')
    if ip and ip != host:
        aHOSTS[host] = ip
    return ip

def bootstrap_udp(lelts, lToxes, oArgs=None):
    lelts = lDNSClean(lelts)
    socket.setdefaulttimeout(15.0)
    for oTox in lToxes:
        random.shuffle(lelts)
        if hasattr(oTox, 'oArgs'):
            oArgs = oTox.oArgs
            if hasattr(oArgs, 'contents') and oArgs.contents.proxy_type != 0:
                lelts = lelts[:1]

#        LOG.debug(f'bootstrap_udp DHT bootstraping {oTox.name} {len(lelts)}')
        for largs in lelts:
            assert len(largs) == 3
            host, port, key = largs
            assert host; assert port; assert key
            if host in lDEAD_BS: continue
            ip = sDNSLookup(host)
            if not ip:
                LOG.warn(f'bootstrap_udp to host={host} port={port} did not resolve ip={ip}')
                continue

            if type(port) == str:
                port = int(port)
            try:
                assert len(key) == 64, key
                # NOT ip
                oRet = oTox.bootstrap(host,
                                     port,
                                     key)
            except Exception as e:
                if oArgs is None or (
                    hasattr(oArgs, 'contents') and oArgs.contents.proxy_type == 0):
                    pass
                    # LOG.error(f'bootstrap_udp failed to host={host} port={port} {e}')
                continue
            if not oRet:
                LOG.warn(f'bootstrap_udp failed to {host} :  {oRet}')
            elif oTox.self_get_connection_status() != TOX_CONNECTION['NONE']:
                LOG.info(f'bootstrap_udp to {host} connected')
                break
            else:
#                LOG.debug(f'bootstrap_udp to {host} not connected')
                pass

def bootstrap_tcp(lelts, lToxes, oArgs=None):
    lelts = lDNSClean(lelts)
    for oTox in lToxes:
        if hasattr(oTox, 'oArgs'): oArgs = oTox.oArgs
        random.shuffle(lelts)
#        LOG.debug(f'bootstrap_tcp bootstapping {oTox.name} {len(lelts)}')
        for (host, port, key,) in lelts:
            assert host; assert port;assert key
            if host in lDEAD_BS: continue
            ip = sDNSLookup(host)
            if not ip:
                LOG.warn(f'bootstrap_tcp to {host} did not resolve ip={ip}')
#                continue
                ip = host
            if host.endswith('.onion') and stem:
                l = lIntroductionPoints(host)
                if not l:
                    LOG.warn(f'bootstrap_tcp to {host} has no introduction points')
                    continue
            if type(port) == str:
                port = int(port)
            try:
                assert len(key) == 64, key
                oRet = oTox.add_tcp_relay(ip,
                                         port,
                                         key)
            except Exception as e:
                LOG.error(f'bootstrap_tcp to {host} : ' +str(e))
                continue
            if not oRet:
                LOG.warn(f'bootstrap_tcp failed to {host} : {oRet}')
            elif oTox.mycon_time == 1:
                LOG.info(f'bootstrap_tcp to {host} not yet connected last=1')
            elif oTox.mycon_status is False:
                LOG.info(f'bootstrap_tcp to {host} not True' \
                         +f" last={int(oTox.mycon_time)}" )
            elif oTox.self_get_connection_status() != TOX_CONNECTION['NONE']:
                LOG.info(f'bootstrap_tcp to {host} connected' \
                         +f" last={int(oTox.mycon_time)}" )
                break
            else:
                LOG.debug(f'bootstrap_tcp to {host} but not connected' \
                         +f" last={int(oTox.mycon_time)}" )
                pass

def iNmapInfoNmap(sProt, sHost, sPort, key=None, environ=None, cmd=''):
    if sHost in ['-', 'NONE']: return 0
    if not nmap: return 0
    nmps = nmap.PortScanner
    if sProt in ['socks', 'socks5', 'tcp4']:
        prot = 'tcp'
        cmd = f" -Pn -n -sT -p T:{sPort}"
    else:
        prot = 'udp'
        cmd = f" -Pn -n -sU -p U:{sPort}"
    LOG.debug(f"iNmapInfoNmap cmd={cmd}")
    sys.stdout.flush()
    o = nmps().scan(hosts=sHost, arguments=cmd)
    aScan = o['scan']
    ip = list(aScan.keys())[0]
    state = aScan[ip][prot][sPort]['state']
    LOG.info(f"iNmapInfoNmap: to {sHost} {state}")
    return 0

def iNmapInfo(sProt, sHost, sPort, key=None, environ=None, cmd='nmap'):
    if sHost in ['-', 'NONE']: return 0
    sFile = os.path.join("/tmp", f"{sHost}.{os.getpid()}.nmap")
    if sProt in ['socks', 'socks5', 'tcp4']:
        cmd += f" -Pn -n -sT -p T:{sPort} {sHost} | grep /tcp "
    else:
        cmd += f" -Pn -n -sU -p U:{sPort} {sHost} | grep /udp "
    LOG.debug(f"iNmapInfo cmd={cmd}")
    sys.stdout.flush()
    iRet = os.system('sudo ' +cmd +f" >{sFile} 2>&1 ")
    LOG.debug(f"iNmapInfo cmd={cmd} iRet={iRet}")
    if iRet != 0:
        return iRet
    assert os.path.exists(sFile), sFile
    with open(sFile, 'rt') as oFd:
        l = oFd.readlines()
    assert len(l)
    l = [line for line in l if line and not line.startswith('WARNING:')]
    s = '\n'.join([s.strip() for s in l])
    LOG.info(f"iNmapInfo: to {sHost}\n{s}")
    return 0

def bootstrap_iNmapInfo(lElts, oArgs, protocol="tcp4", bIS_LOCAL=False, iNODES=iNODES, cmd='nmap'):
    if not bIS_LOCAL and not bAreWeConnected():
        LOG.warn(f"bootstrap_iNmapInfo not local and NOT CONNECTED")
        return True
    if os.environ['USER'] != 'root':
        LOG.warn(f"bootstrap_iNmapInfo not ROOT")
        return True

    lRetval = []
    for elts in lElts[:iNODES]:
        host, port, key = elts
        ip = sDNSLookup(host)
        if not ip:
            LOG.info('bootstrap_iNmapInfo to {host} did not resolve ip={ip}')
            continue
        if type(port) == str:
            port = int(port)
        iRet = -1
        try:
            if not nmap:
                iRet = iNmapInfo(protocol, ip, port, key, cmd=cmd)
            else:
                iRet = iNmapInfoNmap(protocol, ip, port, key)
            if iRet != 0:
                LOG.warn('iNmapInfo to ' +repr(host) +' retval=' +str(iRet))
                lRetval += [False]
            else:
                LOG.debug('iNmapInfo to ' +repr(host) +' retval=' +str(iRet))
                lRetval += [True]
        except Exception as e:
            LOG.exception('iNmapInfo to {host} : ' +str(e)
                          )
            lRetval += [False]
    return any(lRetval)

def caseFactory(cases):
    """We want the tests run in order."""
    if len(cases) > 1:
        ordered_cases = sorted(cases, key=lambda f: inspect.findsource(f)[1])
    else:
        ordered_cases = cases
    return ordered_cases

def suiteFactory(*testcases):
    """We want the tests run in order."""
    linen    = lambda f: getattr(tc, f).__code__.co_firstlineno
    lncmp = lambda a, b: linen(a) - linen(b)

    test_suite = unittest.TestSuite()
    for tc in testcases:
        test_suite.addTest(unittest.makeSuite(tc, sortUsing=lncmp))
    return test_suite
