# -*- mode: python; indent-tabs-mode: nil; py-indent-offset: 4; coding: utf-8 -*-

import os
import sys
import argparse
import re
import logging
import shutil
import json
from ctypes import *
import time, contextlib
import unittest
from random import Random
random = Random()

from PyQt5 import QtCore, QtWidgets
from qtpy.QtWidgets import QApplication

try:
    import coloredlogs
    if 'COLOREDLOGS_LEVEL_STYLES' not in os.environ:
        os.environ['COLOREDLOGS_LEVEL_STYLES'] = 'spam=22;debug=28;verbose=34;notice=220;warning=202;success=118,bold;error=124;critical=background=red'
    # https://pypi.org/project/coloredlogs/
except ImportError as e:
    coloredlogs = False

import wrapper
from wrapper.toxcore_enums_and_consts import TOX_CONNECTION, TOX_USER_STATUS
try:
    from user_data.settings import get_user_config_path
except ImportError:
    get_user_config_path = None

from wrapper_tests.support_http import pick_up_proxy_from_environ, download_url, bAreWeConnected

# LOG=util.log
global LOG
LOG = logging.getLogger('app.'+'ts')

def LOG_ERROR(l): print('ERRORc: '+l)
def LOG_WARN(l):  print('WARNc: ' +l)
def LOG_INFO(l):  print('INFOc: ' +l)
def LOG_DEBUG(l): print('DEBUGc: '+l)
def LOG_TRACE(l): pass # print('TRACE+ '+l)

try:
    from trepan.interfaces import server as Mserver
    from trepan.api import debug
except:
    print('trepan3 TCP server NOT available.')
else:
    print('trepan3 TCP server available.')
    def trepan_handler(num=None, f=None):
        connection_opts={'IO': 'TCP', 'PORT': 6666}
        intf = Mserver.ServerInterface(connection_opts=connection_opts)
        dbg_opts = { 'interface': intf }
        print('Starting TCP server listening on port 6666.')
        debug(dbg_opts=dbg_opts)
        return

# self._audio_thread.isAlive
iTHREAD_TIMEOUT = 1
iTHREAD_SLEEP = 1
iTHREAD_JOINS = 5

lToxSamplerates = [8000, 12000, 16000, 24000, 48000]
lToxSampleratesK = [8, 12, 16, 24, 48]
lBOOLEANS = [
        'local_discovery_enabled',
        'udp_enabled',
        'ipv6_enabled',
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


def assert_main_thread():
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

with ignoreStderr():
    import pyaudio
    oPyA = pyaudio.PyAudio()

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

def oMainArgparser(_=None):
    if not os.path.exists('/proc/sys/net/ipv6'):
        bIpV6 = 'False'
    else:
        bIpV6 = 'True'
    lIpV6Choices=[bIpV6, 'False']

    # need:
    # 'audio_input': oPyA.get_default_input_device_info()['index']
    # 'audio_output': oPyA.get_default_output_device_info()['index']
    audio = get_audio()
    # unfinished

    logfile = os.path.join(os.environ.get('TMPDIR', '/tmp'), 'tests_toxygen.log')

    parser = argparse.ArgumentParser()
    parser.add_argument('--proxy_host', '--proxy-host', type=str,
                        default='',
                        help='proxy host')
    parser.add_argument('--proxy_port', '--proxy-port', default=0, type=int,
                        help='proxy port')
    parser.add_argument('--proxy_type', '--proxy-type', default=0, type=int,
                        choices=[0,1,2],
                        help='proxy type 1=http, 2=socks')
    parser.add_argument('--udp_enabled', type=str, default='True',
                        choices=['True', 'False'],
                        help='En/Disable udp')
    parser.add_argument('--ipv6_enabled', type=str, default=bIpV6,
                        choices=lIpV6Choices,
                        help=f"En/Disable ipv6 - default  {bIpV6}")
    parser.add_argument('--download_nodes_list', type=str, default='False',
                        choices=['True', 'False'],
                        help='Download nodes list')
    parser.add_argument('--nodes_json', type=str,
                        default='')
    parser.add_argument('--network', type=str,
                        choices=['old', 'new', 'local', 'newlocal'],
                        default='new')
    parser.add_argument('--download_nodes_url', type=str,
                        default='https://nodes.tox.chat/json')
    parser.add_argument('--logfile', default=logfile,
                        help='Filename for logging')
    parser.add_argument('--loglevel', default=logging.INFO, type=int,
                        # choices=[logging.info,logging.trace,logging.debug,logging.error]
                        help='Threshold for logging (lower is more) default: 20')
    parser.add_argument('--tcp_port', '--tcp-port', default=0, type=int,
                        help='tcp port')
    parser.add_argument('--mode', type=int, default=2,
                        help='Mode: 0=chat 1=chat+audio 2=chat+audio+video default: 0')
    parser.add_argument('--sleep', type=str, default='time',
                        # could expand this to tk, gtk, gevent...
                        choices=['qt','gevent','time'],
                        help='Sleep method - one of qt, gevent , time')
    return parser

def vOargsToxPreamble(oArgs, Tox, ToxTest):
    kwargs = dict(level=oArgs.loglevel,
                  format='%(levelname)-8s %(message)s')
    if oArgs.logfile:
        kwargs['filename'] = oArgs.logfile
    logging.basicConfig(**kwargs)

    methods = set([x for x in dir(Tox) if not x[0].isupper()
                   and not x[0] == '_'])
    docs = "".join([getattr(ToxTest, x).__doc__ for x in dir(ToxTest)
                    if getattr(ToxTest, x).__doc__ is not None])

    tested = set(re.findall(r't:(.*?)\n', docs))
    not_tested = methods.difference(tested)

    logging.info('Test Coverage: %.2f%%' % (len(tested) * 100.0 / len(methods)))
    if len(not_tested):
        logging.info('Not tested:\n    %s' % "\n    ".join(sorted(list(not_tested))))

def signal_handler(num, f):
    from trepan.interfaces import server as Mserver
    from trepan.api import debug
    connection_opts={'IO': 'TCP', 'PORT': 6666}
    intf = Mserver.ServerInterface(connection_opts=connection_opts)
    dbg_opts = {'interface': intf}
    LOG.info('Starting TCP server listening on port 6666.')
    debug(dbg_opts=dbg_opts)
    return

def merge_args_into_settings(args, settings):
    from user_data.settings import clean_settings
    if args:
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
    if oArgs and hasattr(oArgs, 'nodes_json') and oArgs.nodes_json:
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

def generate_nodes(
                   oArgs=None,
                   nodes_count=DEFAULT_NODES_COUNT,
                   ipv='ipv4',
                   udp_not_tcp=True):
    sFile = _get_nodes_path(oArgs=oArgs)
    return generate_nodes_from_file(sFile,
                                    nodes_count=nodes_count,
                                    ipv=ipv, udp_not_tcp=udp_not_tcp)

aNODES_CACHE = {}
def generate_nodes_from_file(sFile,
                             nodes_count=DEFAULT_NODES_COUNT,
                             ipv='ipv4',
                             udp_not_tcp=True,
                             ):
    """https://github.com/TokTok/c-toxcore/issues/469
I had a conversation with @irungentoo on IRC about whether we really need to call tox_bootstrap() when having UDP disabled and why. The answer is yes, because in addition to TCP relays (tox_add_tcp_relay()), toxcore also needs to know addresses of UDP onion nodes in order to work correctly. The DHT, however, is not used when UDP is disabled. tox_bootstrap() function resolves the address passed to it as argument and calls onion_add_bs_node_path() and DHT_bootstrap() functions. Although calling DHT_bootstrap() is not really necessary as DHT is not used, we still need to resolve the address of the DHT node in order to populate the onion routes with onion_add_bs_node_path() call.
"""
    key = sFile +',' +ipv
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
                    and node['last_ping'] > 0
                    and node["status_tcp"] in [True, "true"]
                    ]
            for (ipv4, ports, public_key,) in elts:
                for port in ports:
                    nodes += [(ipv4, port, public_key)]
        sorted_nodes = sorted(nodes)
        aNODES_CACHE[key] = sorted_nodes
    
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

def bootstrap_local(self, elts):
    if os.path.exists('/run/tox-bootstrapd/tox-bootstrapd.pid'):
        LOG.debug('/run/tox-bootstrapd/tox-bootstrapd.pid')
        iRet = True
    else:
        iRet = os.system("netstat -nle4|grep -q :33")
        if iRet > 0:
            LOG.warn('bootstraping local No local DHT running')
    LOG.info('bootstraping local')
    return bootstrap_good(self, elts)

def bootstrap_good(self, lelts):
    LOG.info('bootstraping udp')
    for elt in ['bob', 'alice']:
        for largs in lelts:
            try:
                oRet = getattr(self, elt).bootstrap(largs[0],
                                                    int(largs[1]),
                                                    largs[2])
            except Exception as e:
                LOG.error('bootstrap to ' +largs[0] +':' +str(largs[1]) \
                          +' ' +str(e))
                continue
            if not oRet:
                LOG.warn('bootstrap failed to ' +largs[0] +' : ' +str(oRet))
            else:
                if getattr(self, elt).self_get_connection_status() != TOX_CONNECTION['NONE']:
                    LOG.debug('bootstrap to ' +largs[0] +' connected')
                    return

def bootstrap_tcp(self, lelts):
    LOG.info('bootstraping tcp')
    for elt in ['alice', 'bob']:
        for largs in lelts:
            try:
                oRet = getattr(self, elt).add_tcp_relay(largs[0],
                                                    int(largs[1]),
                                                    largs[2])
            except Exception as e:
                LOG.error('bootstrap_tcp to ' +largs[0] +' : ' +str(e))
                continue
            if not oRet:
                LOG.warn('bootstrap_tcp failed to ' +largs[0] +' : ' +str(oRet))
            else:
                if getattr(self, elt).self_get_connection_status() != TOX_CONNECTION['NONE']:
                    LOG.debug('bootstrap_tcp to ' +largs[0] +' connected')
                    break

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

    else:
        aKw = dict(level=oArgs.loglevel,
                   format='%(name)s %(levelname)-4s %(message)s')
        if oArgs.logfile:
            aKw['filename'] = oArgs.logfile
        logging.basicConfig(**aKw)

        if oArgs.logfile:
            oHandler = logging.StreamHandler(stream=sys.stdout)
            LOG.addHandler(oHandler)

    logging._defaultFormatter = logging.Formatter(datefmt='%m-%d %H:%M:%S')
    logging._defaultFormatter.default_time_format = '%m-%d %H:%M:%S'
    logging._defaultFormatter.default_msec_format = ''

    LOG.setLevel(oArgs.loglevel)
    LOG.trace = lambda l: LOG.log(0, repr(l))
    LOG.info(f"Setting loglevel to {oArgs.loglevel!s}")

def caseFactory(cases):
    """We want the tests run in order."""
    if len(cases) > 1:
        ordered_cases = sorted(cases, key=lambda f: findsource(f)[1])
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
