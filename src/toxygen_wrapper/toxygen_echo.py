#!/var/local/bin/python3.bash
# -*- mode: python; indent-tabs-mode: nil; py-indent-offset: 4; coding: utf-8 -*-

# A work in progress - chat works, but I don't think AV does.

""" echo.py a basic Tox echo service. Features:
 - accept friend request
 - echo back friend message
# - accept and answer friend call request
# - send back friend audio/video data
# - send back files friend sent
"""

import sys
import os
import traceback
import threading
import random
from ctypes import *
import time
from typing import Union, Callable

# LOG=util.log
global LOG
import logging
# log = lambda x: LOG.info(x)
LOG = logging.getLogger('app')
def LOG_error(a): print('EROR_ '+a)
def LOG_warn(a):  print('WARN_ '+a)
def LOG_info(a):  print('INFO_ '+a)
def LOG_debug(a): print('DBUG_ '+a)
def LOG_trace(a): pass # print('TRAC_ '+a)

from tox_wrapper import tox
import tox_wrapper.toxcore_enums_and_consts as enums
from tox_wrapper.tox import Tox, UINT32_MAX
from tox_wrapper.toxcore_enums_and_consts import TOX_CONNECTION, TOX_USER_STATUS, \
    TOX_MESSAGE_TYPE, TOX_PUBLIC_KEY_SIZE, TOX_FILE_CONTROL, TOX_FILE_KIND

import tox_wrapper.tests.support_testing as ts
from tox_wrapper.tests.support_testing import oMainArgparser

def sleep(fSec) -> None:
    if 'QtCore' in globals():
        if fSec > .000001: QtCore.QThread.msleep(fSec)
        QtCore.QCoreApplication.processEvents()
    else:
        time.sleep(fSec)

try:
    import coloredlogs
    if 'COLOREDLOGS_LEVEL_STYLES' not in os.environ:
        os.environ['COLOREDLOGS_LEVEL_STYLES'] = 'spam=22;debug=28;verbose=34;notice=220;warning=202;success=118,bold;error=124;critical=background=red'
except ImportError as e:
    # logging.log(logging.DEBUG, f"coloredlogs not available:  {e}")
    coloredlogs = None

if 'USER' in os.environ:
    sDATA_FILE = '/tmp/logging_toxygen_' +os.environ['USER'] +'.tox'
elif 'USERNAME' in os.environ:
    sDATA_FILE = '/tmp/logging_toxygen_' +os.environ['USERNAME'] +'.tox'
else:
    sDATA_FILE = '/tmp/logging_toxygen_' +'data' +'.tox'

bHAVE_AV = False
iDHT_TRIES = 100
iDHT_TRY = 0

#?SERVER = lLOCAL[-1]

if not bHAVE_AV:
    class AV(): pass
else:
    class AV(tox.ToxAV):
        def __init__(self, core):
            super(AV, self).__init__(core)
            self.core = self.get_tox()

        def on_call(self, fid:int, audio_enabled:bool, video_enabled:bool) -> None:
            LOG.info("Incoming %s call from %d:%s ..." % (
                "video" if video_enabled else "audio",
                fid,
                self.core.friend_get_name(fid)))
            bret = self.answer(fid, 48, 64)
            LOG.info(f"Answered, in call... {bret}")

        def on_call_state(self, fid:int, state:int) -> None:
            LOG.info('call state:fn=%d, state=%d' % (fid, state))

        def on_audio_bit_rate(self, fid:int, audio_bit_rate:int) -> None:
            LOG.info('audio bit rate status: fn=%d, abr=%d' %
                  (fid, audio_bit_rate))

        def on_video_bit_rate(self, fid:int, video_bit_rate:int) -> None:
            LOG.info('video bit rate status: fn=%d, vbr=%d' %
                  (fid, video_bit_rate))

        def on_audio_receive_frame(self, fid:int,
                                   pcm:int,
                                   sample_count:int,
                                   channels:int,
                                   sampling_rate:int) -> None:
            # LOG.info('audio frame: %d, %d, %d, %d' %
            #      (fid, sample_count, channels, sampling_rate))
            # LOG.info('pcm len:%d, %s' % (len(pcm), str(type(pcm))))
            sys.stdout.write('.')
            sys.stdout.flush()
            bret = self.audio_send_frame(fid, pcm, sample_count,
                                         channels, sampling_rate)
            if bret is False:
                LOG.error('on_audio_receive_frame error.')

        def on_video_receive_frame(self, fid:int, width:int, height:int, frame, u, v) -> None:
            LOG.info('video frame: %d, %d, %d, ' % (fid, width, height))
            sys.stdout.write('*')
            sys.stdout.flush()
            bret = self.video_send_frame(fid, width, height, frame, u, v)
            if bret is False:
                LOG.error('on_video_receive_frame error.')

        def witerate(self) -> None:
            self.iterate()


def save_to_file(tox, fname: str) -> None:
    data = tox.get_savedata()
    with open(fname, 'wb') as f:
        f.write(data)

def load_from_file(fname: str) -> bytes:
    assert os.path.exists(fname)
    return open(fname, 'rb').read()

class EchoBot():
    def __init__(self, oTox):
        self._tox = oTox
        self._tox.self_set_name("PyEchoBot")
        LOG.info(f'ID: {self._tox.self_get_address()}')

        self.files = {}
        self.av = None
        self.on_connection_status = None

    def start(self) -> None:
        self.connect()
        if bHAVE_AV:
            # RuntimeError: Attempted to create a second session for the same Tox instance.

            self.av = True # AV(self._tox_pointer)
        def bobs_on_friend_request(iTox,
                                     public_key,
                                     message_data,
                                     message_data_size,
                                     *largs) -> None:
            key = ''.join(chr(x) for x in public_key[:TOX_PUBLIC_KEY_SIZE])
            sPk = tox.bin_to_string(key, TOX_PUBLIC_KEY_SIZE)
            sMd = str(message_data, 'UTF-8')
            LOG.debug('on_friend_request ' +sPk +' ' +sMd)
            self.on_friend_request(sPk, sMd)
        LOG.info('setting bobs_on_friend_request')
        self._tox.callback_friend_request(bobs_on_friend_request)

        def bobs_on_friend_message(iTox,
                                   iFriendNum,
                                   iMessageType,
                                   message_data,
                                   message_data_size,
                                   *largs) -> None:
            sMd = str(message_data, 'UTF-8')
            LOG_debug(f"on_friend_message  {iFriendNum}" +' ' +sMd)
            self.on_friend_message(iFriendNum, iMessageType, sMd)
        LOG.info('setting bobs_on_friend_message')
        self._tox.callback_friend_message(bobs_on_friend_message)

        def bobs_on_file_chunk_request(iTox, fid, filenumber, position, length, *largs) -> None:
            if length == 0:
                return

            data = self.files[(fid, filenumber)]['f'][position:(position + length)]
            self._tox.file_send_chunk(fid, filenumber, position, data)
        self._tox.callback_file_chunk_request(bobs_on_file_chunk_request)

        def bobs_on_file_recv(iTox, fid, filenumber, kind, size, filename, *largs):
            LOG_info(f"on_file_recv {fid} {filenumber} {kind} {size} {filename}")
            if size == 0:
                return
            self.files[(fid, filenumber)] = {
                'f': bytes(),
                'filename': filename,
                'size': size
            }
            self._tox.file_control(fid, filenumber, TOX_FILE_CONTROL['RESUME'])


    def connect(self) -> None:
        if not self.on_connection_status:
            def on_connection_status(iTox, iCon, *largs) -> None:
                LOG_info('ON_CONNECTION_STATUS - CONNECTED ' + repr(iCon))
            self._tox.callback_self_connection_status(on_connection_status)
            LOG.info('setting on_connection_status callback ')
            self.on_connection_status = on_connection_status
        if self._oargs.network in ['newlocal', 'local']:
            LOG.info('connecting on the new network ')
            sNet = 'newlocal'
        elif self._oargs.network == 'new':
            LOG.info('connecting on the new network ')
            sNet = 'new'
        else: # main old
            LOG.info('connecting on the old network ')
            sNet = 'old'
        sFile = self._oargs.nodes_json
        lNodes = ts.generate_nodes_from_file(sFile)
        lElts = lNodes
        random.shuffle(lElts)
        for lElt in lElts[:10]:
            status = self._tox.self_get_connection_status()
            try:
                if self._tox.bootstrap(*lElt):
                    LOG.info('connected to ' + lElt[0]+' '+repr(status))
                else:
                    LOG.warn('failed connecting to ' + lElt[0])
            except Exception as e:
                LOG.warn('error connecting to ' + lElt[0])

        if self._oargs.proxy_type > 0:
            random.shuffle(lElts)
            for lElt in lElts[:10]:
                status = self._tox.self_get_connection_status()
                try:
                    if self._tox.add_tcp_relay(*lElt):
                        LOG.info('relayed to ' + lElt[0] +' '+repr(status))
                    else:
                        LOG.warn('failed relay to ' + lElt[0])
                except Exception as e:
                    LOG.warn('error relay to ' + lElt[0])

    def loop(self) -> None:
        if not self.av:
            self.start()
        checked = False
        save_to_file(self._tox, sDATA_FILE)

        LOG.info('Starting loop.')
        while True:

            status = self._tox.self_get_connection_status()
            if not checked and status:
                LOG.info('Connected to DHT.')
                checked = True
            if not checked and not status:
                global iDHT_TRY
                iDHT_TRY += 10
                self.connect()
                self.iterate(100)
                if iDHT_TRY >= iDHT_TRIES:
                    raise RuntimeError("Failed to connect to the DHT.")
                LOG.warn(f"NOT Connected to DHT. {iDHT_TRY}")
                checked = True
            if checked and not status:
                LOG.info('Disconnected from DHT.')
                self.connect()
                checked = False

            if bHAVE_AV:
                True # self.av.witerate()
            self.iterate(100)

        LOG.info('Ending loop.')

    def iterate(self, n:int = 100) -> None:
        interval = self._tox.iteration_interval()
        for i in range(n):
            self._tox.iterate()
            sleep(interval / 1000.0)
            self._tox.iterate()

    def on_friend_request(self, pk: Union[bytes,str], message: Union[bytes,str]) -> None:
        LOG.debug('Friend request from %s: %s' % (pk, message))
        self._tox.friend_add_norequest(pk)
        LOG.info('on_friend_request Accepted.')
        save_to_file(self._tox, sDATA_FILE)

    def on_friend_message(self, friendId: int, message_type: int, message: Union[bytes,str]) -> None:
        name = self._tox.friend_get_name(friendId)
        LOG.debug(f"{name}, {message}, {message_type}")
        yMessage = bytes(message, 'UTF-8')
        self._tox.friend_send_message(friendId, TOX_MESSAGE_TYPE['NORMAL'], yMessage)
        LOG.info('EchoBot sent: %s' % message)

    def on_file_recv_chunk(self, fid: int, filenumber, position, data) -> None:
        filename = self.files[(fid, filenumber)]['filename']
        size = self.files[(fid, filenumber)]['size']
        LOG.debug(f"on_file_recv_chunk {fid} {filenumber} {filename} {position/float(size)*100}")

        if data is None:
            msg = "I got '{}', sending it back right away!".format(filename)
            self._tox.friend_send_message(fid, TOX_MESSAGE_TYPE['NORMAL'], msg)

            self.files[(fid, 0)] = self.files[(fid, filenumber)]

            length = self.files[(fid, filenumber)]['size']
            self._tox.file_send(fid, TOX_FILE_KIND['DATA'], length, filename)

            del self.files[(fid, filenumber)]
            return

        self.files[(fid, filenumber)]['f'] += data

class App():
    def __init__(self):
        self.mode = 0
oAPP = App()

class EchobotTox(Tox):

    def __init__(self, opts, app=None):

        super().__init__(opts, app=app)
        self._address = self.self_get_address()
        self.name = 'pyechobot'
        self._opts = opts
        self._app = app

class BaseThread(threading.Thread):

    def __init__(self, name=None, target=None):
        if name:
            super().__init__(name=name, target=target)
        else:
            super().__init__(target=target)
        self._stop_thread = False
        self.name = name

    def stop_thread(self, timeout=-1) -> None:
        self._stop_thread = True
        if timeout < 0:
            timeout = ts.iTHREAD_TIMEOUT
        i = 0
        while i < ts.iTHREAD_JOINS:
            self.join(timeout)
            if not self.is_alive(): break
            i = i + 1
        else:
            LOG.warning(f"{self.name} BLOCKED")

class ToxIterateThread(BaseThread):

    def __init__(self, tox):
        super().__init__(name='ToxIterateThread')
        self._tox = tox

    def run(self) -> None:
        while not self._stop_thread:
            self._tox.iterate()
            sleep(self._tox.iteration_interval() / 1000)

def oArgparse(lArgv):
    parser = ts.oMainArgparser()
    parser.add_argument('profile', type=str, nargs='?', default=None,
                        help='Path to Tox profile')
    oArgs = parser.parse_args(lArgv)
    ts.clean_booleans(oArgs)

    if hasattr(oArgs, 'sleep'):
        if oArgs.sleep == 'qt':
            pass # broken or gevent.sleep(idle_period)
        elif oArgs.sleep == 'gevent':
            pass # broken or gevent.sleep(idle_period)
        else:
            oArgs.sleep = 'time'

    return oArgs

def iMain(oArgs) -> int:
    global sDATA_FILE
    # oTOX_OPTIONS = ToxOptions()
    global oTOX_OPTIONS
    oMainArgparser
    oTOX_OPTIONS = ts.oToxygenToxOptions(oArgs)
    opts = oTOX_OPTIONS
    if coloredlogs:
        coloredlogs.install(
                            level=oArgs.loglevel,
                            logger=LOG,
                            # %(asctime)s,%(msecs)03d %(hostname)s [%(process)d]
                            fmt='%(name)s %(levelname)s %(message)s'
                        )
    else:
        if 'logfile' in oArgs:
            logging.basicConfig(filename=oArgs.logfile,
                                level=oArgs.loglevel,
                                format='%(levelname)-8s %(message)s')
        else:
            logging.basicConfig(level=oArgs.loglevel,
                                format='%(levelname)-8s %(message)s')

    iRet = 0
    if hasattr(oArgs,'profile') and oArgs.profile and os.path.isfile(oArgs.profile):
        sDATA_FILE = oArgs.profile
        LOG.info(f"loading from  {sDATA_FILE}")
        opts.savedata_data = load_from_file(sDATA_FILE)
        opts.savedata_length = len(opts.savedata_data)
        opts.savedata_type = enums.TOX_SAVEDATA_TYPE['TOX_SAVE']
    else:
        opts.savedata_data = None

    try:
        oTox = EchobotTox(opts, app=oAPP)
        t = EchoBot(oTox)
        t._oargs = oArgs
        t.start()
        t.loop()
        save_to_file(t._tox, sDATA_FILE)
    except KeyboardInterrupt:
        save_to_file(t._tox, sDATA_FILE)
    except RuntimeError as e:
        LOG.error(f"ERROR  {e}")
        iRet = 1
    except Exception as e:
        LOG.error(f"EXCEPTION  {e}")
        LOG.warn(' iMain(): ' \
                     +'\n' + traceback.format_exc())
        iRet = 1
    return iRet

def main(lArgs=None) -> int:
    global oTOX_OARGS
    global oTOX_OPTIONS
    global bIS_LOCAL
    if lArgs is None: lArgs = []
    oArgs = oArgparse(lArgs)
    bIS_LOCAL = oArgs.network in ['newlocal', 'localnew', 'local']
    oTOX_OARGS = oArgs
    setattr(oTOX_OARGS, 'bIS_LOCAL', bIS_LOCAL)
    oTOX_OPTIONS = ts.oToxygenToxOptions(oArgs)
    if coloredlogs:
        # https://pypi.org/project/coloredlogs/
        coloredlogs.install(level=oArgs.loglevel,
                        logger=LOG,
                        # %(asctime)s,%(msecs)03d %(hostname)s [%(process)d]
                        fmt='%(name)s %(levelname)s %(message)s'
                        )
    else:
        logging.basicConfig(level=oArgs.loglevel) #  logging.INFO

    return iMain(oArgs)

if __name__ == '__main__':
    try:
        i = main(sys.argv[1:])
    except KeyboardInterrupt as e:
        i = 0
    except Exception as e:
        i = 1
    sys.exit(i)
