# -*- mode: python; indent-tabs-mode: nil; py-indent-offset: 4; coding: utf-8 -*-

import os
import sys
import argparse
import re
import logging
import urllib
import json
from ctypes import *
from io import BytesIO
import time, contextlib
import unittest
from random import Random
random = Random()

try:
    import pycurl
except ImportError:
    pycurl = None
try:
    import requests
except ImportError:
    requests = None

from PyQt5 import QtCore, QtWidgets
from qtpy.QtWidgets import QApplication

import wrapper
from wrapper.toxcore_enums_and_consts import TOX_CONNECTION, TOX_USER_STATUS
try:
    from user_data.settings import get_user_config_path
except ImportError:
    get_user_config_path = None

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
CONNECT_TIMEOUT = 20.0

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
    'download_nodes_list']
lBOOLEANS = [
        'local_discovery_enabled',
        'udp_enabled',
        'ipv6_enabled',
        'compact_mode',
        'allow_inline',
        'notifications',
        'sound_notifications',
        'hole_punching_enabled',
        'dht_announcements_enabled',
        'save_history',
        'download_nodes_list'
        'core_logging',
        ]


def bAreWeConnected(): 
    # FixMe: Linux
    sFile = f"/proc/{os.getpid()}/net/route"
    if not os.path.isfile(sFile): return None
    i = 0
    for elt in open(sFile, "r").readlines():
        if elt.startswith('Iface'): continue
        if elt.startswith('lo'): continue
        i += 1
    return i > 0

lNEW = [ # ngc_jfreeg2:
        ('104.244.74.69', 38445, # tox.plastiras.org
         '5E47BA1DC3913EB2CBF2D64CE4F23D8BFE5391BFABE5C43C5BAD13F0A414CD77'),
        ('172.93.52.70', 33445,
         '79CADA4974B0926F286F025CD5FFDF3E654A3758C53E0273ECFC4D12C21DCA48'),
        ]

lGOOD = [
    ("95.79.50.56",
     33445,
     "8E7D0B859922EF569298B4D261A8CCB5FEA14FB91ED412A7603A585A25698832"),
    ("85.143.221.42",
     33445,
     "DA4E4ED4B697F2E9B000EEFE3A34B554ACD3F45F5C96EAEA2516DD7FF9AF7B43"),
    ("tox.verdict.gg",
     33445,
     "1C5293AEF2114717547B39DA8EA6F1E331E5E358B35F9B6B5F19317911C5F976"),
    ("tox.initramfs.io",
     33445,
     "3F0A45A268367C1BEA652F258C85F4A66DA76BCAA667A49E770BCC4917AB6A25"),
    ("144.217.167.73",
     33445,
     "7E5668E0EE09E19F320AD47902419331FFEE147BB3606769CFBE921A2A2FD34C"),
    ("tox.abilinski.com",
     33445,
     "10C00EB250C3233E343E2AEBA07115A5C28920E9C8D29492F6D00B29049EDC7E"),
    ("tox.novg.net",
     33445,
     "D527E5847F8330D628DAB1814F0A422F6DC9D0A300E6C357634EE2DA88C35463"),
    ("198.199.98.108",
     33445,
     "BEF0CFB37AF874BD17B9A8F9FE64C75521DB95A37D33C5BDB00E9CF58659C04F"),
    ('82.196.15.215',  33445, # tox.kurnevsky.net
     "82EF82BA33445A1F91A7DB27189ECFC0C013E06E3DA71F588ED692BED625EC23"),
    ("81.169.136.229",
     33445,
     "E0DB78116AC6500398DDBA2AEEF3220BB116384CAB714C5D1FCD61EA2B69D75E"),
    ("tox2.abilinski.com",
     33445,
     "7A6098B590BDC73F9723FC59F82B3F9085A64D1B213AAF8E610FD351930D052D"),
    ("bg.tox.dcntrlzd.network",
     33445,
     "20AD2A54D70E827302CDF5F11D7C43FA0EC987042C36628E64B2B721A1426E36"),
    ("46.101.197.175",
     33445,
     "CD133B521159541FB1D326DE9850F5E56A6C724B5B8E5EB5CD8D950408E95707"),
    ("tox1.mf-net.eu",
     33445,
     "B3E5FA80DC8EBD1149AD2AB35ED8B85BD546DEDE261CA593234C619249419506"),
    ("tox2.mf-net.eu",
     33445,
     "70EA214FDE161E7432530605213F18F7427DC773E276B3E317A07531F548545F"),
    ("195.201.7.101",
     33445,
     "B84E865125B4EC4C368CD047C72BCE447644A2DC31EF75BD2CDA345BFD310107"),
    ("gt.sot-te.ch",
     33445,
     "F4F4856F1A311049E0262E9E0A160610284B434F46299988A9CB42BD3D494618"),
    ("5.19.249.240",
     38296,
     "DA98A4C0CD7473A133E115FEA2EBDAEEA2EF4F79FD69325FC070DA4DE4BA3238"),
    ("188.225.9.167",
     33445,
     "1911341A83E02503AB1FD6561BD64AF3A9D6C3F12B5FBB656976B2E678644A67"),
    ("122.116.39.151",
     33445,
     "5716530A10D362867C8E87EE1CD5362A233BAFBBA4CF47FA73B7CAD368BD5E6E"),
    ("195.123.208.139",
     33445,
     "534A589BA7427C631773D13083570F529238211893640C99D1507300F055FE73"),
    ("104.225.141.59",
     43334,
     "933BA20B2E258B4C0D475B6DECE90C7E827FE83EFA9655414E7841251B19A72C"),
    ("139.162.110.188",
     33445,
     "F76A11284547163889DDC89A7738CF271797BF5E5E220643E97AD3C7E7903D55"),
    ("198.98.49.206",
     33445,
     "28DB44A3CEEE69146469855DFFE5F54DA567F5D65E03EFB1D38BBAEFF2553255"),
    ("172.105.109.31",
     33445,
     "D46E97CF995DC1820B92B7D899E152A217D36ABE22730FEA4B6BF1BFC06C617C"),
    ("ru.tox.dcntrlzd.network",
     33445,
     "DBB2E896990ECC383DA2E68A01CA148105E34F9B3B9356F2FE2B5096FDB62762"),
    ("91.146.66.26",
     33445,
     "B5E7DAC610DBDE55F359C7F8690B294C8E4FCEC4385DE9525DBFA5523EAD9D53"),
    ("tox01.ky0uraku.xyz",
     33445,
     "FD04EB03ABC5FC5266A93D37B4D6D6171C9931176DC68736629552D8EF0DE174"),
    ("tox02.ky0uraku.xyz",
     33445,
     "D3D6D7C0C7009FC75406B0A49E475996C8C4F8BCE1E6FC5967DE427F8F600527"),
    ("tox.plastiras.org",
     33445,
     "8E8B63299B3D520FB377FE5100E65E3322F7AE5B20A0ACED2981769FC5B43725"),
    ("141.95.108.234",
     33445,
     "2DEF3156812324B1593A6442C937EAE0A8BD98DE529D2D4A7DD4BA6CB3ECF262"),
    ("kusoneko.moe",
     33445,
     "BE7ED53CD924813507BA711FD40386062E6DC6F790EFA122C78F7CDEEE4B6D1B"),
    ("tox2.plastiras.org",
     33445,
     "B6626D386BE7E3ACA107B46F48A5C4D522D29281750D44A0CBA6A2721E79C951"),
    ("tox.plastiras.org",
     33445,
     "8E8B63299B3D520FB377FE5100E65E3322F7AE5B20A0ACED2981769FC5B43725"),
    ("141.95.108.234",
     33445,
     "2DEF3156812324B1593A6442C937EAE0A8BD98DE529D2D4A7DD4BA6CB3ECF262"),
    ("kusoneko.moe",
     33445,
     "BE7ED53CD924813507BA711FD40386062E6DC6F790EFA122C78F7CDEEE4B6D1B"),
    ('84.22.115.205', 33445, # tox.verdict.gg
     '1C5293AEF2114717547B39DA8EA6F1E331E5E358B35F9B6B5F19317911C5F976'),
]

lRELAYS = [
    ("tox02.ky0uraku.xyz",33445, "D3D6D7C0C7009FC75406B0A49E475996C8C4F8BCE1E6FC5967DE427F8F600527"),
    ("tox.plastiras.org",   443, "8E8B63299B3D520FB377FE5100E65E3322F7AE5B20A0ACED2981769FC5B43725"),
    ("46.101.197.175",    33445, "CD133B521159541FB1D326DE9850F5E56A6C724B5B8E5EB5CD8D950408E95707"),
    ("122.116.39.151",     3389, "5716530A10D362867C8E87EE1CD5362A233BAFBBA4CF47FA73B7CAD368BD5E6E"),
    ("172.105.109.31",    33445, "D46E97CF995DC1820B92B7D899E152A217D36ABE22730FEA4B6BF1BFC06C617C"),
    ("178.62.250.138",    33445, "788236D34978D1D5BD822F0A5BEBD2C53C64CC31CD3149350EE27D4D9A2F9B6B"),
    ("198.46.138.44",     33445, "F404ABAA1C99A9D37D61AB54898F56793E1DEF8BD46B1038B9D822E8460FAB67"),
    ("51.15.37.145",      33445, "6FC41E2BD381D37E9748FC0E0328CE086AF9598BECC8FEB7DDF2E440475F300E"),
    ("130.133.110.14",    33445, "461FA3776EF0FA655F1A05477DF1B3B614F7D6B124F7DB1DD4FE3C08B03B640F"),
    ("198.98.51.198",     33445, "1D5A5F2F5D6233058BF0259B09622FB40B482E4FA0931EB8FD3AB8E7BF7DAF6F"),
    ("108.61.165.198",    33445, "8E7D0B859922EF569298B4D261A8CCB5FEA14FB91ED412A7603A585A25698832"),
    ("185.25.116.107",    33445, "DA4E4ED4B697F2E9B000EEFE3A34B554ACD3F45F5C96EAEA2516DD7FF9AF7B43"),
    ("5.189.176.217",      5190, "2B2137E094F743AC8BD44652C55F41DFACC502F125E99E4FE24D40537489E32F"),
    ("217.182.143.254",    2306, "7AED21F94D82B05774F697B209628CD5A9AD17E0C073D9329076A4C28ED28147"),
    ("104.223.122.15",    33445, "0FB96EEBFB1650DDB52E70CF773DDFCABE25A95CC3BB50FC251082E4B63EF82A"),
    ("d4rk4.ru",           1813, "53737F6D47FA6BD2808F378E339AF45BF86F39B64E79D6D491C53A1D522E7039"),
    ("104.233.104.126",   33445, "EDEE8F2E839A57820DE3DA4156D88350E53D4161447068A3457EE8F59F362414"),
    ("51.254.84.212",     33445, "AEC204B9A4501412D5F0BB67D9C81B5DB3EE6ADA64122D32A3E9B093D544327D"),
    ("88.99.133.52",      33445, "2D320F971EF2CA18004416C2AAE7BA52BF7949DB34EA8E2E21AF67BD367BE211"),
    ("185.58.206.164",    33445, "24156472041E5F220D1FA11D9DF32F7AD697D59845701CDD7BE7D1785EB9DB39"),
    ("92.54.84.70",       33445, "5625A62618CB4FCA70E147A71B29695F38CC65FF0CBD68AD46254585BE564802"),
    ("195.93.190.6",      33445, "FB4CE0DDEFEED45F26917053E5D24BDDA0FA0A3D83A672A9DA2375928B37023D"),
    ("tox.uplinklabs.net", 33445, "1A56EA3EDF5DF4C0AEABBF3C2E4E603890F87E983CAC8A0D532A335F2C6E3E1F"),
    ("95.215.44.78",      33445, "672DBE27B4ADB9D5FB105A6BB648B2F8FDB89B3323486A7A21968316E012023C"),
    ("163.172.136.118",   33445, "2C289F9F37C20D09DA83565588BF496FAB3764853FA38141817A72E3F18ACA0B"),
    ("sorunome.de",       33445, "02807CF4F8BB8FB390CC3794BDF1E8449E9A8392C5D3F2200019DA9F1E812E46"),
    ("37.97.185.116",     33445, "E59A0E71ADA20D35BD1B0957059D7EF7E7792B3D680AE25C6F4DBBA09114D165"),
    ("193.124.186.205",   5228,  "9906D65F2A4751068A59D30505C5FC8AE1A95E0843AE9372EAFA3BAB6AC16C2C"),
    ("80.87.193.193",     33445, "B38255EE4B054924F6D79A5E6E5889EC94B6ADF6FE9906F97A3D01E3D083223A"),
    ("hibiki.eve.moe",    33445, "D3EB45181B343C2C222A5BCF72B760638E15ED87904625AAD351C594EEFAE03E"),
    ("46.229.52.198",     33445, "813C8F4187833EF0655B10F7752141A352248462A567529A38B6BBF73E979307"),
    ("144.217.86.39",     33445, "7E5668E0EE09E19F320AD47902419331FFEE147BB3606769CFBE921A2A2FD34C"),
    ("77.37.160.178",     33440, "CE678DEAFA29182EFD1B0C5B9BC6999E5A20B50A1A6EC18B91C8EBB591712416"),
    ("85.21.144.224",     33445, "8F738BBC8FA9394670BCAB146C67A507B9907C8E564E28C2B59BEBB2FF68711B"),
    ("95.215.46.114",     33445, "5823FB947FF24CF83DDFAC3F3BAA18F96EA2018B16CC08429CB97FA502F40C23"),
]

lBAD = [('xxx.garbage.zzz', 33445,
         '0123456789114717547B39DA8EA6F1E331E5E358B35F9B6B5F19317911C5F976',),
        ('www.google.com', 33445, # no port
         '0123456789114717547B39DA8EA6F1E331E5E358B35F9B6B5F19317911C5F976',),
        ('www.google.com', 80, # no ToX port
          '0123456789114717547B39DA8EA6F1E331E5E358B35F9B6B5F19317911C5F976',)]

lLOCAL = [# /etc/init.d/tox-bootstrapd.conf
          ('127.0.0.1', 33446,
           'EC8F7405F79F281569B6C66D9F03490973AB99BC9175C44FBEF4C3428A63B80D'),
          ('127.0.0.1', 33447,
           'EC8F7405F79F281569B6C66D9F03490973AB99BC9175C44FBEF4C3428A63B80D'),
          ('127.0.0.1', 3389,
           'EC8F7405F79F281569B6C66D9F03490973AB99BC9175C44FBEF4C3428A63B80D'),
          # /var/local/src/c-toxcore/build/DHT_bootstrap
          ('127.0.0.1', 33445,
           '6DB2DEA1785F4A7AEAB52F1F4BC90D6266FBC375DEF316DED59F4E814F97F438'),
          # /var/local/src/toxcore/build/DHT_bootstrap
          ('127.0.0.1', 33445,
           'A22E68642917F424E5B38E98CACE38A4906B67228D83E507084400B597D5722E'),
           ]

lNO_PROXY = ['localhost', '127.0.0.1']

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
        LOG.handle(o)
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
        LOG.trace(f"{level}: {message}")

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

def should_we_pick_up_proxy_from_environ():
    retval = dict()
    if os.environ.get('socks_proxy', ''):
        # socks_proxy takes precedence over https/http
        proxy = os.environ.get('socks_proxy', '')
        i = proxy.find('//')
        if i >= 0: proxy = proxy[i+2:]
        retval['proxy_host'] = proxy.split(':')[0]
        retval['proxy_port'] = proxy.split(':')[-1]
        retval['proxy_type'] = 2
        retval['udp_enabled'] = False
    elif os.environ.get('https_proxy', ''):
        # https takes precedence over http
        proxy = os.environ.get('https_proxy', '')
        i = proxy.find('//')
        if i >= 0: proxy = proxy[i+2:]
        retval['proxy_host'] = proxy.split(':')[0]
        retval['proxy_port'] = proxy.split(':')[-1]
        retval['proxy_type'] = 1
        retval['udp_enabled'] = False
    elif os.environ.get('http_proxy', ''):
        proxy = os.environ.get('http_proxy', '')
        i = proxy.find('//')
        if i >= 0: proxy = proxy[i+2:]
        retval['proxy_host'] = proxy.split(':')[0]
        retval['proxy_port'] = proxy.split(':')[-1]
        retval['proxy_type'] = 1
        retval['udp_enabled'] = False
    return retval

def download_url(url, app):
    if not bAreWeConnected(): return ''

    settings = app._settings
    if pycurl:
        LOG.debug('nodes loading with pycurl: ' + str(url))
        buffer = BytesIO()
        c = pycurl.Curl()
        c.setopt(c.URL, url)
        c.setopt(c.WRITEDATA, buffer)
        # Follow redirect.
        c.setopt(c.FOLLOWLOCATION, True)

        # cookie jar
        cjar = os.path.join(os.environ['HOME'], '.local', 'jar.cookie')
        if os.path.isfile(cjar):
            c.setopt(c.COOKIEFILE, cjar)
            # LARGS+=(  --cookie-jar  --junk-session-cookies )

        #? c.setopt(c.ALTSVC_CTRL, 16)

        c.setopt(c.NOPROXY, ','.join(lNO_PROXY))
        #? c.setopt(c.CAINFO, certifi.where())
        if settings['proxy_type'] == 2 and settings['proxy_host']:
            socks_proxy = 'socks5h://'+settings['proxy_host']+':'+str(settings['proxy_port'])
            settings['udp_enabled'] = False
            c.setopt(c.PROXY, socks_proxy)
            c.setopt(c.PROXYTYPE, pycurl.PROXYTYPE_SOCKS5_HOSTNAME)
        elif settings['proxy_type'] == 1 and settings['proxy_host']:
            https_proxy = 'https://'+settings['proxy_host']+':'+str(settings['proxy_port'])
            c.setopt(c.PROXY, https_proxy)
        elif settings['proxy_type'] == 1 and settings['proxy_host']:
            http_proxy = 'http://'+settings['proxy_host']+':'+str(settings['proxy_port'])
            c.setopt(c.PROXY, http_proxy)
        c.setopt(c.PROTOCOLS, c.PROTO_HTTPS)
        try:
            c.perform()
            c.close()
            #? assert c.getinfo(c.RESPONSE_CODE) < 300
            result = buffer.getvalue()
            # Body is a byte string.
            LOG_INFO('nodes loaded with pycurl: ' + str(url))
            return result
        except Exception as ex:
            LOG_ERROR('TOX nodes loading error with pycurl: ' + str(ex))
            # drop through

    if requests:
        LOG_DEBUG('nodes loading with requests: ' + str(url))
        try:
            headers = dict()
            headers['Content-Type'] = 'application/json'
            proxies = dict()
            if settings['proxy_type'] == 2 and settings['proxy_host']:
                socks_proxy = 'socks5://'+settings['proxy_host']+':'+str(settings['proxy_port'])
                settings['udp_enabled'] = False
                proxies['https'] = socks_proxy
            elif settings['proxy_type'] == 1 and settings['proxy_host']:
                https_proxy = 'https://'+settings['proxy_host']+':'+str(settings['proxy_port'])
                proxies['https'] = https_proxy
            elif settings['proxy_type'] == 1 and settings['proxy_host']:
                http_proxy = 'http://'+settings['proxy_host']+':'+str(settings['proxy_port'])
                proxies['http'] = http_proxy
            req = requests.get(url,
                               headers=headers,
                               proxies=proxies,
                               timeout=CONNECT_TIMEOUT)
                               # max_retries=3
            assert req.status_code < 300
            result = req.content
            LOG_INFO('nodes loaded with requests: ' + str(url))
            return result
        except Exception as ex:
            LOG_ERROR('TOX nodes loading error with requests: ' + str(ex))
            # drop through

    if not settings['proxy_type']:  # no proxy
        LOG_DEBUG('nodes loading with no proxy: ' + str(url))
        try:
            req = urllib.request.Request(url)
            req.add_header('Content-Type', 'application/json')
            response = urllib.request.urlopen(req)
            result = response.read()
            LOG_INFO('nodes loaded with no proxy: ' + str(url))
            return result
        except Exception as ex:
            LOG_ERROR('TOX nodes loading ' + str(ex))
        return ''
    else:  # proxy
        from PyQt5 import QtNetwork

        LOG_DEBUG(f"TOX nodes loading with QT proxy: {url}")
        netman = QtNetwork.QNetworkAccessManager()
        proxy = QtNetwork.QNetworkProxy()
        proxy.setType(
            QtNetwork.QNetworkProxy.Socks5Proxy if settings['proxy_type'] == 2 \
            else QtNetwork.QNetworkProxy.HttpProxy )
        proxy.setHostName(settings['proxy_host'])
        proxy.setPort(settings['proxy_port'])
        netman.setProxy(proxy)
        try:
            request = QtNetwork.QNetworkRequest()
            request.setUrl(QtCore.QUrl(url))
            reply = netman.get(request)

            while not reply.isFinished():
                QtCore.QThread.msleep(1)
                QtCore.QCoreApplication.processEvents()
            result = bytes(reply.readAll().data())
            LOG_INFO('TOX nodes loading with QT proxy: ' + str(url))
            return result
        except Exception as ex:
            LOG_ERROR('TOX nodes loading error with proxy: ' + str(ex))
        return ''

def _get_nodes_path(oArgs=None):
    if oArgs and hasattr(oArgs, 'nodes_json') and oArgs.nodes_json:
        LOG.debug("_get_nodes_path: " +oArgs.nodes_json)
        return oArgs.nodes_json
    default = os.path.join(get_user_config_path(), 'toxygen_nodes.json')
    LOG.debug("_get_nodes_path: " +default)
    return default

DEFAULT_NODES_COUNT = 4

def generate_nodes(nodes_count=DEFAULT_NODES_COUNT, oArgs=None):
    sFile = _get_nodes_path(oArgs=oArgs)
    return generate_nodes_from_file(sFile, nodes_count)

def generate_nodes_from_file(sFile, nodes_count=DEFAULT_NODES_COUNT):
    if not os.path.exists(sFile):
        LOG.error("generate_nodes_from_file file not found " +sFile)
        return []
    LOG.info("generate_nodes_from_file " +sFile)
    with open(sFile, 'rt') as fl:
        json_nodes = json.loads(fl.read())['nodes']
    nodes = [(node['ipv4'], node['port'], node['public_key'],) for
             node in json_nodes if node['ipv4'] != 'NONE']
    sorted_nodes = nodes
    random.shuffle(sorted_nodes)
    if nodes_count is not None and len(sorted_nodes) > nodes_count:
        sorted_nodes = sorted_nodes[-nodes_count:]
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
