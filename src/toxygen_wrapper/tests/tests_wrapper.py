# -*- mode: python; indent-tabs-mode: nil; py-indent-offset: 4; coding: utf-8 -*-
#
# @file   tests.py
# @author Wei-Ning Huang (AZ) <aitjcize@gmail.com>
#
# Copyright (C) 2013 - 2014 Wei-Ning Huang (AZ) <aitjcize@gmail.com>
# All Rights reserved.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software Foundation,
# Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#

"""Originaly from https://github.com/oxij/PyTox c-toxcore-02 branch
which itself was forked from https://github.com/aitjcize/PyTox/

Modified to work with toxygen_wrapper

these tests create the alice and bob Toxes for each testcase.
We could do it once for the testsuite but we are testing a ctypes wrapper
and what we think we've seen is errors in the wrapper can corrupt memory
that shows as a SEGV but not nesessarily right-away: could be a little later.
So for cleanliness and purity we remake the Toxes, which means we have to
wait in each test to get connected, which can be slow over tor: ~40 sec. is
not unusual, but less for directly connected.

So typically this testsuite takes ~1000 sec. direct and 1300 sec. over Tor,
but Tor can have bad weeks so these Tor times could double or triple.

We should consirder reusing a tox profile between testcases to cache the peers.

"""

import ctypes
import faulthandler
import hashlib
import logging
import os
import random
import re
import sys
import threading
import traceback
import unittest
from ctypes import *
from typing import Union, Callable, Union

faulthandler.enable()

import warnings
warnings.filterwarnings('ignore')

try:
    from io import BytesIO
    import certifi
    import pycurl
except ImportError:
    pycurl = None

# from pyannotate_runtime import collect_types

try:
    import coloredlogs
    os.environ['COLOREDLOGS_LEVEL_STYLES'] = 'spam=22;debug=28;verbose=34;notice=220;warning=202;success=118,bold;error=124;critical=background=red'
except ImportError as e:
    logging.log(logging.DEBUG, f"coloredlogs not available:  {e}")
    coloredlogs = None

try:
    import color_runner
except ImportError as e:
    logging.log(logging.DEBUG, f"color_runner not available:  {e}")
    color_runner = None

import tox_wrapper
import tox_wrapper.toxcore_enums_and_consts as enums
from tox_wrapper.tox import Tox, UINT32_MAX, ToxError

from tox_wrapper.toxcore_enums_and_consts import (TOX_ADDRESS_SIZE, TOX_CONNECTION,
                                              TOX_FILE_CONTROL,
                                              TOX_MESSAGE_TYPE,
                                              TOX_SECRET_KEY_SIZE,
                                              TOX_USER_STATUS)

try:
    import support_testing as ts
except ImportError:
    import tox_wrapper.tests.support_testing as ts

try:
    from tests.toxygen_tests import test_sound_notification
    bIS_NOT_TOXYGEN = False
except ImportError:
    bIS_NOT_TOXYGEN = True

# from PyQt5 import QtCore
import time

sleep = time.sleep

global LOG
LOG = logging.getLogger('TestS')
if False:
    def LOG_ERROR(l: str) -> None: LOG.error('+ '+l)
    def LOG_WARN(l: str) -> None: LOG.warn('+ '+l)
    def LOG_INFO(l: str) -> None: LOG.info('+ '+l)
    def LOG_DEBUG(l: str) -> None: LOG.debug('+ '+l)
    def LOG_TRACE(l: str) -> None: pass # print('+ '+l)
else:
    # just print to stdout so there is NO complications from logging.
    def LOG_ERROR(l: str) -> None: print('EROR+ '+l)
    def LOG_WARN(l: str) -> None: print('WARN+ '+l)
    def LOG_INFO(l: str) -> None: print('INFO+ '+l)
    def LOG_DEBUG(l: str) -> None: print('DEBUG+ '+l)
    def LOG_TRACE(l: str) -> None: pass # print('TRAC+ '+l)

ADDR_SIZE = 38 * 2
CLIENT_ID_SIZE = 32 * 2
THRESHOLD = 120 # >25
fSOCKET_TIMEOUT = 15.0

iN = 6

global     oTOX_OPTIONS
oTOX_OPTIONS = {}

bIS_LOCAL = 'new' in sys.argv or 'local' in sys.argv or 'newlocal' in sys.argv

def expectedFailure(test_item):
    test_item.__unittest_expecting_failure__ = True
    return test_item

def expectedFail(reason: str):
    """
    expectedFailure with a reason
    """
    def decorator(test_item):
        test_item.__unittest_expecting_failure__ = True
        return test_item
    return decorator

class ToxOptions():
    def __init__(self):
        self.ipv6_enabled = True
        self.udp_enabled = True
        self.proxy_type = 0
        self.proxy_host = ''
        self.proxy_port = 0
        self.start_port = 0
        self.end_port = 0
        self.tcp_port = 0
        self.savedata_type = 0  # 1=toxsave, 2=secretkey
        self.savedata_data = b''
        self.savedata_length = 0
        self.local_discovery_enabled = False
        self.dht_announcements_enabled = True
        self.hole_punching_enabled = False
        self.experimental_thread_safety = False

class App():
    def __init__(self):
        self.mode = 0
oAPP = App()

class AliceTox(Tox):

    def __init__(self, opts, args, app=None):

        super(AliceTox, self).__init__(opts, app=app)
        self._address = self.self_get_address()
        self.name = 'alice'
        self._opts = opts
        self._app = app
        self._args = args

class BobTox(Tox):

    def __init__(self, opts, args, app=None):
        super(BobTox, self).__init__(opts, app=app)
        self._address = self.self_get_address()
        self.name = 'bob'
        self._opts = opts
        self._app = app
        self._args = args

class BaseThread(threading.Thread):

    def __init__(self, name=None, target=None):
        if name:
            super().__init__(name=name, target=target)
        else:
            super().__init__(target=target)
        self._stop_thread = False
        self.name = name

    def stop_thread(self, timeout: int = -1) -> None:
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

def prepare(self):

    def bobs_on_self_connection_status(iTox, connection_state, *args) -> None:
        status = connection_state
        self.bob.dht_connected = status
        self.bob.mycon_time = time.time()
        try:
            if status != TOX_CONNECTION['NONE']:
                LOG_INFO(f"bobs_on_self_connection_status TRUE {status}" \
                          +f" last={int(self.bob.mycon_time)}" )
                self.bob.mycon_status = True
            else:
                LOG_DEBUG(f"bobs_on_self_connection_status FALSE {status}" \
                          +f" last={int(self.bob.mycon_time)}" )
                self.bob.mycon_status = False
        except Exception as e:
            LOG_ERROR(f"bobs_on_self_connection_status {e}")
        else:
            if self.bob.self_get_connection_status() != status:
                LOG_WARN(f"bobs_on_self_connection_status DISAGREE {status}")

    def alices_on_self_connection_status(iTox, connection_state: int, *args) -> None:
        global oTOX_OARGS
        #FixMe connection_num
        status = connection_state
        self.alice.dht_connected = status
        self.alice.mycon_time = time.time()
        try:
            if status != TOX_CONNECTION['NONE']:
                LOG_INFO(f"alices_on_self_connection_status TRUE {status}" \
                          +f" last={int(self.alice.mycon_time)}" )
                self.alice.mycon_status = True
            else:
                LOG_DEBUG(f"alices_on_self_connection_status FALSE {status}" \
                          +f" last={int(self.alice.mycon_time)}" )
                self.alice.mycon_status = False
        except Exception as e:
            LOG_ERROR(f"alices_on_self_connection_status error={e}")

    opts = oTestsToxOptions(oTOX_OARGS)

    alice = AliceTox(opts, oTOX_OARGS, app=oAPP)
    alice.dht_connected = -1
    alice.mycon_status = False
    alice.mycon_time = 1
    alice.callback_self_connection_status(alices_on_self_connection_status)

    # only bob logs trace_enabled
    if oTOX_OARGS.trace_enabled:
        LOG.info(f"toxcore trace_enabled")
        ts.vAddLoggerCallback(opts)
    else:
        LOG.debug(f"toxcore trace_enabled=False")

    bob = BobTox(opts, oTOX_OARGS, app=oAPP)
    bob.dht_connected = -1
    bob.mycon_status = False
    bob.mycon_time = 1
    bob.callback_self_connection_status(bobs_on_self_connection_status)
    if not bIS_LOCAL and not ts.bAreWeConnected():
        LOG.warning(f"doOnce not local and NOT CONNECTED")
    return [bob, alice]

from wrapper_mixin import WrapperMixin

class ToxSuite(unittest.TestCase, WrapperMixin):
    failureException = AssertionError

    def setUp(self):
        if not hasattr(self, 'alice') and not hasattr(self, 'bob'):
            l = prepare(self)
            assert l
            self.bob, self.alice = l
        if not hasattr(self.bob, '_main_loop'):
#?            self.bob._main_loop = ToxIterateThread(self.bob)
#?            self.bob._main_loop.start()
            LOG.debug(f"self.bob._main_loop: ") # {threading.enumerate()}
        if not hasattr(self.alice, '_main_loop'):
#?            self.alice._main_loop = ToxIterateThread(self.alice)
#?            self.alice._main_loop.start()
            LOG.debug(f"self.alice._main_loop: ") # {threading.enumerate()}

        self.bBobNeedAlice()
        self.bAliceNeedAddBob()

    def run(self, result=None) -> None:
        """ Stop after first error """
        if result and not result.errors:
            super(ToxSuite, self).run(result)

    @classmethod
    def setUpClass(cls) -> None:
        global oTOX_OARGS
        assert oTOX_OPTIONS

        cls.lUdp = ts.generate_nodes(
            oArgs=oTOX_OARGS,
            nodes_count=2*ts.iNODES,
            ipv='ipv4',
            udp_not_tcp=True)

        cls.lTcp = ts.generate_nodes(
            oArgs=oTOX_OARGS,
            nodes_count=2*ts.iNODES,
            ipv='ipv4',
            udp_not_tcp=False)

    def tearDown(self) -> None:
        """
        """
        if hasattr(self, 'bob') and self.bob.self_get_friend_list_size() >= 1:
            LOG.warn(f"tearDown BOBS STILL HAS A FRIEND LIST {self.bob.self_get_friend_list()}")
            for elt in self.bob.self_get_friend_list():
                self.bob.friend_delete(elt)
        if hasattr(self, 'alice') and self.alice.self_get_friend_list_size() >= 1:
            LOG.warn(f"tearDown ALICE STILL HAS A FRIEND LIST {self.alice.self_get_friend_list()}")
            for elt in self.alice.self_get_friend_list():
                self.alice.friend_delete(elt)

#        LOG.debug(f"tearDown threads={threading.active_count()}")
        if hasattr(self, 'bob'):
            self.bob.callback_self_connection_status(None)
            if hasattr(self.bob, 'main_loop'):
                self.bob._main_loop.stop_thread()
                del self.bob._main_loop
#            self.bob.kill()
            del         self.bob
        if hasattr(self, 'alice'):
            self.alice.callback_self_connection_status(None)
            if hasattr(self.alice, 'main_loop'):
                self.alice._main_loop.stop_thread()
                del self.alice._main_loop
#            self.alice.kill()
            del         self.alice

    @classmethod
    def tearDownClass(cls) -> None:
        if hasattr(cls, 'bob'):
            cls.bob._main_loop.stop_thread()
            cls.bob.kill()
            del         cls.bob
        if hasattr(cls, 'alice'):
            cls.alice._main_loop.stop_thread()
            cls.alice.kill()
            del         cls.alice

    # tests are executed in order
    def test_notice_log(self) -> None: # works
        notice = '/var/lib/tor/.SelekTOR/3xx/cache/9050/notice.log'
        if os.path.exists(notice):
            iRet = os.system(f"sudo sed -e '1,/.notice. Bootstrapped 100%/d' {notice}" + \
                              "| grep 'Tried for 120 seconds to get a connection to :0.'")
            if iRet == 0:
                raise SystemExit("seconds to get a connection to :0")
            else:
                LOG.debug(f"checked {notice}")

    def test_tests_logging(self): # works
        with self.assertLogs('foo', level='INFO') as cm:
            logging.getLogger('foo').info('first message')
            logging.getLogger('foo.bar').error('second message')
            logging.getLogger('foo.bar.baz').debug('third message')
            self.assertEqual(cm.output, ['INFO:foo:first message',
                                         'ERROR:foo.bar:second message'])

    def test_hash(self): # works
        otox = self.bob
        string = 'abcdef'
        name = otox.hash(bytes(string, 'utf-8'))
        assert name
        string = b'abcdef'
        name = otox.hash(string)
        assert name
        LOG.info(f"test_hash: {string} -> {name} ")

    def test_tests_start(self) -> None: # works
        """
        t:hash
        t:kill
        t:libtoxcore
        t:options_default
        t:options_free
        t:options_new
        t:self_get_toxid
    """
        LOG.info("test_tests_start " )
        port = ts.tox_bootstrapd_port()

        assert len(self.bob._address) == 2*TOX_ADDRESS_SIZE, len(self.bob._address)
        assert len(self.alice._address) == 2*TOX_ADDRESS_SIZE, \
            len(self.alice._address)

        assert self.bob.self_get_address() == self.bob._address
        assert self.alice.self_get_address() == self.alice._address

    def test_bootstrap_local_netstat(self) -> None: # works
        """
        t:callback_file_chunk_request
        t:callback_file_recv
        t:callback_file_recv_chunk
        t:callback_file_recv_control
        t:callback_friend_connection_status
        t:callback_friend_lossless_packet
        t:callback_friend_lossy_packet
        t:callback_friend_message
        t:callback_friend_name
        t:callback_friend_read_receipt
        t:callback_friend_request
        t:callback_friend_status
        t:callback_friend_status_message
        t:callback_friend_typing
        t:callback_group_custom_packet
        t:callback_group_invite
        """
        if oTOX_OARGS.network not in ['new', 'newlocal', 'local']:
            return

        port = ts.tox_bootstrapd_port()
        if not port:
            return
        iStatus = os.system(f"""netstat -nle4 | grep :{port}""")
        if iStatus == 0:
            LOG.info(f"bootstrap_local_netstat port {port} iStatus={iStatus}")
        else:
            LOG.warning(f"bootstrap_local_netstat NOT {port} iStatus={iStatus}")

    def test_bootstrap_local(self, fsocket_timeout:float = fSOCKET_TIMEOUT) -> bool: # works
        """
        t:call_bootstrap
        t:add_tcp_relay
        t:self_get_dht_id
        """
        # get port from /etc/tox-bootstrapd.conf 33445
        self.call_bootstrap(fsocket_timeout=fsocket_timeout)
        # ts.bootstrap_local(self, self.lUdp)
        i = 0
        iStatus = -1
        while i < 10:
            i = i + 1
            iStatus = self.bob.self_get_connection_status()
            if iStatus != TOX_CONNECTION['NONE']:
                break
            sleep(3)
        else:
            pass

        o1 = self.alice.self_get_dht_id()
        assert len(o1) == 64
        o2 = self.bob.self_get_dht_id()
        assert len(o2) == 64

#        if o1 != o2:  LOG.warning(f"bootstrap_local DHT NOT same {o1} {o2} iStatus={iStatus}")

        iStatus = self.bob.self_get_connection_status()
        if iStatus != TOX_CONNECTION['NONE']:
            LOG.info(f"bootstrap_local connected iStatus={iStatus}")
            return True
        iStatus = self.alice.self_get_connection_status()
        if iStatus != TOX_CONNECTION['NONE']:
            LOG.info(f"bootstrap_local connected iStatus={iStatus}")
            return True
        LOG.warning(f"bootstrap_local NOT CONNECTED iStatus={iStatus}")
        return False

    @unittest.skipIf(os.geteuid() != 0, 'must be root')
    def test_bootstrap_iNmapInfo(self) -> None: # works
        global oTOX_OARGS
#        if os.environ['USER'] != 'root':
#            return
        iStatus = self.bob.self_get_connection_status()
        LOG.info(f"test_bootstrap_iNmapInfo connected bob iStatus={iStatus}")
        if oTOX_OARGS.network in ['new', 'newlocal', 'localnew']:
            lElts = self.lUdp
        elif oTOX_OARGS.proxy_port > 0:
            lElts = self.lTcp
        else:
            lElts = self.lUdp
        lRetval = []
        random.shuffle(lElts)
        # assert
        ts.bootstrap_iNmapInfo(lElts, oTOX_OARGS, "tcp4", bIS_LOCAL=bIS_LOCAL, iNODES=8)

    def test_self_get_secret_key(self) -> None: # works
        """
        t:self_get_secret_key
        """
        # test_self_get_secret_key
        CRYPTO_SECRET_KEY_SIZE         = 32
        secret_key = create_string_buffer(CRYPTO_SECRET_KEY_SIZE)
        oRet0 =  self.alice.self_get_secret_key(secret_key)
        assert oRet0, repr(oRet0)
        LOG.info('test_self_get_secret_key ' +repr(oRet0))
        assert len(str(oRet0))
        del secret_key

    def test_self_get_public_keys(self) -> None: # works
        """
        t:self_get_secret_key
        t:self_get_public_key
        """

        LOG.info('test_self_get_public_keys self.alice.self_get_secret_key')
        oRet0 = self.alice.self_get_secret_key()
        assert len(oRet0)
        LOG.info('test_self_get_public_keys ' +repr(oRet0))
        oRet1 = self.alice.self_get_public_key()
        assert len(oRet1)
        LOG.info('test_self_get_public_keys ' +repr(oRet1))
        assert oRet0 != oRet1, repr(oRet0) +' != ' +repr(oRet1)

    def test_self_name(self) -> None: # works
        """
        t:self_set_name
        t:self_get_name
        t:self_get_name_size
        """
        self.alice.self_set_name('Alice')
        assert self.alice.self_get_name() == 'Alice'
        assert self.alice.self_get_name_size() == len('Alice')
        self.bob.self_set_name('Bob')
        assert self.bob.self_get_name() == 'Bob'
        assert self.bob.self_get_name_size() == len('Bob')

    @unittest.skip('loud')
    @unittest.skipIf(bIS_NOT_TOXYGEN or oTOX_OARGS.mode == 0, 'not testing in toxygen')
    def test_sound_notification(self) -> None: # works
        """
        Plays sound notification
        :param  type of notification
        """
        from tests.toxygen_tests import test_sound_notification
        test_sound_notification(self)

    def test_address(self) -> None: # works
        """
        t:self_get_address
        t:self_get_nospam
        t:self_set_nospam
        t:self_get_keys
        """
        assert len(self.alice.self_get_address()) == ADDR_SIZE
        assert len(self.bob.self_get_address()) == ADDR_SIZE

        self.alice.self_set_nospam(0x12345678)
        assert self.alice.self_get_nospam() == 0x12345678
        self.loop(50)

        if hasattr(self.alice, 'self_get_keys'):
            pk, sk = self.alice.self_get_keys()
            assert pk == self.alice.self_get_address()[:CLIENT_ID_SIZE]

    def test_status_message(self) -> None: # works
        """
        t:self_get_status_message
        t:self_get_status_message_size
        """
        MSG = 'Happy'
        self.alice.self_set_status_message(MSG)
        self.loop(100)
        assert self.alice.self_get_status_message() == MSG, \
            self.alice.self_get_status_message() +' is not ' +MSG
        assert self.alice.self_get_status_message_size() == len(MSG)

    def test_self_get_udp_port(self) -> None: # works
        """
        t:self_get_udp_port
        """
        if hasattr(oTOX_OPTIONS, 'udp_port') and oTOX_OPTIONS.udp_port:
            o = self.alice.self_get_udp_port()
            LOG.info('self_get_udp_port alice ' +repr(o))
            assert o > 0
            o = self.bob.self_get_udp_port()
            LOG.info('self_get_udp_port bob ' +repr(o))
            assert o > 0

    def test_self_get_tcp_port(self) -> None: # works
        """
        t:self_get_tcp_port
        """
        if hasattr(oTOX_OPTIONS, 'tcp_port') and oTOX_OPTIONS.tcp_port:
            # errors if tcp_port <= 0
            o = self.alice.self_get_tcp_port()
            LOG.info('self_get_tcp_port ' +repr(o))
            o = self.bob.self_get_tcp_port()
            LOG.info('self_get_tcp_port ' +repr(o))

    def test_get_dht_id(self) -> None: # works
        """
        t:self_get_dht_id
        """
        o1 = self.alice.self_get_dht_id()
        assert len(o1) == 64
        o2 = self.bob.self_get_dht_id()
        assert len(o2) == 64

    def test_bob_add_alice_as_friend_norequest(self) -> None: # works
        """
        t:friend_delete
        t:friend_exists
        t:friend_add_norequest
        t:friend_get_public_key
        t:self_get_friend_list
        t:self_get_friend_list_size
        """
        i = len(self.bob.self_get_friend_list())
        assert self.bob_add_alice_as_friend_norequest()
        assert len(self.bob.self_get_friend_list()) == i + 1
        #: Test last online
        assert self.bob.friend_get_last_online(self.baid) is not None
        if hasattr(self, 'baid') and self.baid >= 0:
            self.bob.friend_delete(self.baid)


    def test_alice_add_bob_as_friend_norequest(self) -> None: # works - intermittent failures
        """
        t:friend_delete
        t:friend_exists
        t:friend_get_public_key
        t:self_get_friend_list
        t:self_get_friend_list_size
        """
        i = len(self.alice.self_get_friend_list())
        assert self.alice_add_bob_as_friend_norequest()
        assert len(self.alice.self_get_friend_list()) == i + 1
        #: Test last online
        assert self.alice.friend_get_last_online(self.abid) is not None
        if hasattr(self, 'abid') and self.abid >= 0:
            self.alice.friend_delete(self.abid)

    def test_both_add_as_friend_norequest(self) -> None: # works
        """
        t:friend_delete
        t:friend_exists
        t:friend_get_public_key
        t:self_get_friend_list
        t:self_get_friend_list_size
        """
        try:
            self.both_add_as_friend_norequest()
            assert len(self.bob.self_get_friend_list()) > 0
            assert len(self.alice.self_get_friend_list()) > 0
        except AssertionError as e:
            LOG.error(f"Failed test {e}")
            raise
        except Exception as e:
            LOG.error(f"Failed test {e}")
            raise
        finally:
            if hasattr(self, 'baid') and self.baid >= 0:
                self.bob.friend_delete(self.baid)
            assert len(self.bob.self_get_friend_list()) == 0
            if hasattr(self, 'abid') and self.abid >= 0:
                self.alice.friend_delete(self.abid)
            assert len(self.alice.self_get_friend_list()) == 0

    def test_loop_until_connected(self) -> None: # works
        assert self.loop_until_connected()

    def test_bob_add_alice_as_friend_and_status(self) -> None:
        """
        t:friend_delete
        t:friend_exists
        t:friend_get_public_key
        t:self_get_friend_list
        t:self_get_friend_list_size
        """
        self.bob_add_alice_as_friend_and_status()
        if hasattr(self, 'baid') and self.baid >= 0:
            self.bob.friend_delete(self.baid)

    @unittest.skip('unfinished')
    def test_alice_add_bob_as_friend_and_status(self) -> None:
        assert self.alice_add_bob_as_friend_and_status()
        if hasattr(self, 'abid') and self.abid >= 0:
            self.alice.friend_delete(self.abid)

    def test_bob_assert_connection_status(self) -> None: # works
        if self.bob.self_get_connection_status() == TOX_CONNECTION['NONE']:
            AssertionError("ERROR: NOT CONNECTED " \
                         +repr(self.bob.self_get_connection_status()))

    def test_alice_assert_connection_status(self) -> None: # works
        if self.alice.self_get_connection_status() == TOX_CONNECTION['NONE']:
            AssertionError("ERROR: NOT CONNECTED " \
                         +repr(self.alice.self_get_connection_status()))

    def test_bob_assert_mycon_status(self) -> None: # works
        if self.bob.mycon_status == False:
            AssertionError("ERROR: NOT CONNECTED " \
                         +repr(self.bob.mycon_status))

    def test_alice_assert_mycon_status(self) -> None: # works
        if self.alice.mycon_status == False:
            AssertionError("ERROR: NOT CONNECTED " \
                         +repr(self.alice.mycon_status))

    def test_bob_add_alice_as_friend(self) -> None: # works?
        try:
            if self.bob._args.norequest:
                assert self.bob_add_alice_as_friend_norequest()
            else:
                assert self.bob_add_alice_as_friend()
            #: Test last online
            assert self.bob.friend_get_last_online(self.baid) is not None
        except AssertionError as e:
            LOG.error(f"Failed test {e}")
            raise
        except Exception as e:
            LOG.error(f"Failed test {e}")
            raise
        finally:
            if hasattr(self, 'baid') and self.baid >= 0:
                self.bob.friend_delete(self.baid)
            if len(self.bob.self_get_friend_list()) > 0:
                LOG.warn(f"WTF bob.self_get_friend_list() {bob.self_get_friend_list()}")

    def test_alice_add_bob_as_friend(self) -> None: # works!
        try:
            if self.bob._args.norequest:
                assert self.alice_add_bob_as_friend_norequest()
            else:
                assert self.alice_add_bob_as_friend()
            #: Test last online
            assert self.alice.friend_get_last_online(self.abid) is not None
        except AssertionError as e:
            #WTF?
            if hasattr(self, 'abid') and self.abid >= 0:
                self.alice.friend_delete(self.abid)
            LOG.error(f"Failed test {e}")
            raise
        except Exception as e:
            #WTF?
            LOG.error(f"test_alice_add_bob_as_friend EXCEPTION  {e}")
            raise
        finally:
            if hasattr(self, 'baid') and self.baid >= 0:
                self.bob.friend_delete(self.baid)
            if hasattr(self, 'abid') and self.abid >= 0:
                self.alice.friend_delete(self.abid)
            if len(self.alice.self_get_friend_list()) > 0:
                LOG.warn(f"WTF alice.self_get_friend_list() {alice.self_get_friend_list()}")

    def test_both_add_as_friend(self) -> None: # works
        try:
            if self.bob._args.norequest:
                assert self.both_add_as_friend_norequest()
            else:
                assert self.both_add_as_friend()
        except AssertionError as e:
            LOG.warn(f"Failed test {e}")
            raise
        except Exception as e:
            LOG.error(f"test_both_add_as_friend EXCEPTION  {e}")
            raise
        finally:
            if hasattr(self,'baid') and self.baid >= 0:
                self.bob.friend_delete(self.baid)
            if hasattr(self,'abid') and self.abid >= 0:
                self.alice.friend_delete(self.abid)

    def test_groups_join(self) -> None:
        """
         t:group_join
         t:group_disconnect
         t:group_leave
         t:group_self_set_name
         """
        if not self.get_connection_status():
            LOG.warning(f"test_groups_join NOT CONNECTED")
            self.loop_until_connected(self.bob)

        iGrp = self.otox_test_groups_join(self.bob)
        LOG.info(f"test_groups_join iGrp={iGrp}")
        assert iGrp >= 0, f"test_groups_join iGrp={iGrp}"
        try:
            self.bob.group_disconnect(iGrp)
        except Exception as e:
            LOG.error(f"bob.group_disconnect EXCEPTION  {e}")
            raise
        try:
            self.bob.group_leave(iGrp, None)
        except Exception as e:
            LOG.error(f"bob.group_leave EXCEPTION  {e}")
            raise

    def test_groups(self) -> None:
        """
         t:group_new
         t:group_disconnect
         t:group_get_name
         t:group_get_name_size
         t:group_get_topic
         t:group_get_topic_size
         t:group_get_privacy_state
         t:group_self_set_name
         t:group_get_number_groups

         t:group_founder_set_password
         t:group_founder_set_peer_limit
         t:group_founder_set_privacy_state
         t:group_get_chat_id
         t:group_get_password
         t:group_get_password_size
         t:group_get_peer_limit
         t:group_invite_accept
         t:group_invite_friend
         t:group_is_connected
         t:group_leave
         t:group_mod_set_role
        """
        iGrp = self.otox_test_groups(self.bob)
        LOG.info(f"test_groups iGrp={iGrp}")
        if iGrp >= 0:
            try:
                self.bob.group_disconnect(iGrp)
            except Exception as e:
                LOG.error(f"bob.group_disconnect EXCEPTION  {e}")
                raise
            try:
                self.bob.group_leave(iGrp, None)
            except Exception as e:
                LOG.error(f"bob.group_leave EXCEPTION  {e}")
                raise

#!    @expectedFail('fails') # assertion fails on == MSG
    def test_on_friend_status_message(self) -> None: # fails
        """
        t:self_set_status_message
        t:self_get_status_message
        t:self_get_status_message_size
        t:friend_set_status_message
        t:friend_get_status_message
        t:friend_get_status_message_size
        t:on_friend_status_message
        """
        MSG = 'Happy'
        sSlot = 'friend_status_message'

        def bob_on_friend_status_message(iTox, friend_id, new_status_message, new_status_size, *largs) -> None:
            LOG_INFO(f"BOB_ON_friend_status_message friend_id={friend_id} " \
                     +f"new_status_message={new_status_message}")
            try:
                assert str(new_status_message, 'UTF-8') == MSG
                assert friend_id == self.baid
            except Exception as e:
                LOG_ERROR(f"BOB_ON_friend_status_message EXCEPTION {e}")
            setattr(self.bob, sSlot, True)

        setattr(self.bob, sSlot, None)
        try:
            if self.bob._args.norequest:
                assert self.bob_add_alice_as_friend_norequest()
                assert self.alice_add_bob_as_friend_norequest()
            else:
                # no not connected error
                assert self.bob_add_alice_as_friend()
                assert self.alice_add_bob_as_friend_norequest()
            # need a friend connected?
            if not self.get_connection_status():
                LOG.warning(f"test_groups_join NOT CONNECTED")
                self.loop_until_connected(self.bob)

            self.bob.callback_friend_status_message(bob_on_friend_status_message)
            self.warn_if_no_cb(self.bob, sSlot)
            status_message = bytes(MSG, 'utf-8')
            self.alice.self_set_status_message(status_message)
            if not self.wait_otox_attrs(self.bob, [sSlot]):
                LOG_WARN(f"on_friend_status_message NO {sSlot}")

            assert self.bob.friend_get_status_message(self.baid) == MSG, \
              f"message={self.bob.friend_get_status_message(self.baid)}"
            assert self.bob.friend_get_status_message_size(self.baid) == len(MSG), \
              f"message_len={self.bob.friend_get_status_message_size(self.baid)}"

        except AssertionError as e:
            LOG.error(f"test_on_friend_status_message FAILED {e}")
            raise
        except Exception as e:
            LOG.error(f"test_on_friend_status_message EXCEPTION  {e}")
            raise
        finally:
            self.bob.callback_friend_status(None)
            if hasattr(self, 'baid') and self.baid >= 0:
                self.bob.friend_delete(self.baid)
            if hasattr(self, 'abid') and self.abid >= 0:
                self.alice.friend_delete(self.abid)

    def test_friend(self) -> None: # works! sometimes
        """
        t:friend_get_name
        t:friend_get_name_size
        t:on_friend_name
         """

        try:
            #: Test friend request
            if self.bob._args.norequest:
                assert self.bob_add_alice_as_friend_norequest()
                assert self.alice_add_bob_as_friend_norequest()
            else:
                # no not connected error
                assert self.bob_add_alice_as_friend()
                assert self.alice_add_bob_as_friend_norequest()

            a = self.alice.self_get_address()[:CLIENT_ID_SIZE]
            assert self.bob.friend_get_public_key(self.baid) == a, \
              LOG.error(f"test_friend BAID  {a}")
            del a

            #: Test friend_get_public_key
            b = self.bob.self_get_address()[:CLIENT_ID_SIZE]
            assert self.alice.friend_get_public_key(self.abid) == b, \
              LOG.error(f"test_friend ABID  {b}")
            del b
        except AssertionError as e:
            LOG.error(f"Failed test {e}")
            raise
        except Exception as e:
            LOG.error(f"test_friend EXCEPTION  {e}")
            raise
        finally:
            if hasattr(self, 'baid') and self.baid >= 0:
                self.bob.friend_delete(self.baid)
            if hasattr(self, 'abid') and self.abid >= 0:
                self.alice.friend_delete(self.abid)

    @expectedFail('fails') # assert self.bob.friend_get_status(self.baid) == TOX_USER_STATUS['BUSY']
    def test_user_status(self) -> None: # fails
        """
        t:self_get_status
        t:self_set_status
        t:friend_get_status
        t:friend_get_status
        t:on_friend_status
        """
        sSlot = 'friend_status'

        setattr(self.bob, sSlot, None)
        def bobs_on_friend_set_status(iTox, friend_id, new_status, *largs) -> None:
            LOG_INFO(f"bobs_on_friend_set_status {friend_id} {new_status}")
            try:
                assert friend_id == self.baid
                assert new_status in [TOX_USER_STATUS['BUSY'], TOX_USER_STATUS['AWAY']]
            except Exception as e:
                LOG_WARN(f"bobs_on_friend_set_status EXCEPTION {e}")
            setattr(self.bob, sSlot, True)

        try:
            if self.bob._args.norequest:
                assert self.bob_add_alice_as_friend_norequest()
            else:
                assert self.bob_add_alice_as_friend()
            if not self.get_connection_status():
                LOG.warning(f"test_user_status NOT CONNECTED self.get_connection_status")
                self.loop_until_connected(self.bob)

            self.bob.callback_friend_status(bobs_on_friend_set_status)
            self.warn_if_no_cb(self.bob, sSlot)
            sSTATUS = TOX_USER_STATUS['BUSY']
            self.alice.self_set_status(sSTATUS)
            if not self.wait_otox_attrs(self.bob, [sSlot]):
                # malloc(): unaligned tcache chunk detected
                LOG_WARN(f'test_user_status NO {sSlot}')

            assert self.bob.friend_get_status(self.baid) == TOX_USER_STATUS['BUSY'], \
              f"friend_get_status {self.bob.friend_get_status(self.baid)} != {TOX_USER_STATUS['BUSY']}"

        except AssertionError as e:
            LOG.error(f"test_user_status FAILED {e}")
            raise
        except Exception as e:
            LOG.error(f"test_user_status EXCEPTION  {e}")
            raise
        finally:
            self.bob.callback_friend_status(None)
            self.warn_if_cb(self.bob, sSlot)
            if hasattr(self, 'baid') and self.baid >= 0:
                self.bob.friend_delete(self.baid)

    @unittest.skip('crashes')
    def test_kill_remake(self) -> None:
        """
        t:friend_get_kill_remake
        t:on_friend_connection_status
        """
        global oTOX_OARGS
        sSlot = 'friend_connection_status'
        setattr(self.bob, sSlot, None)
        def bobs_on_friend_connection_status(iTox, friend_id, iStatus, *largs):
            LOG_INFO(f"bobs_on_friend_connection_status " +repr(iStatus))
            try:
                assert friend_id == self.baid
            except Exception as e:
                LOG_ERROR(f"bobs_on_friend_connection_status ERROR  {e}")
            setattr(self.bob, sSlot, True)

        opts = oTestsToxOptions(oTOX_OARGS)
        setattr(self.bob, sSlot, True)
        try:
            if self.bob._args.norequest:
                assert self.bob_add_alice_as_friend_norequest()
            else:
                assert self.bob_add_alice_as_friend()

            self.bob.callback_friend_connection_status(bobs_on_friend_connection_status)

            LOG.info("test_kill_remake killing alice")
            self.alice.kill() #! bang
            LOG.info("test_kill_remake making alice")
            self.alice = Tox(opts, app=oAPP)
            LOG.info("test_kill_remake maked alice")

            if not self.wait_otox_attrs(self.bob, [sSlot]):
                LOG_WARN(f'test_kill_remake NO {sSlot}')
        except AssertionError as e:
            LOG.error(f"test_kill_remake Failed test {e}")
            raise
        except Exception as e:
            LOG.error(f"bobs_on_friend_connection_status  {e}")
            raise
        finally:
            self.bob.callback_friend_connection_status(None)
            if hasattr(self, 'baid') and self.baid >= 0:
                self.bob.friend_delete(self.baid)

    def test_alice_typing_status(self) -> None: # works
        """
        t:on_friend_read_receipt
        t:on_friend_typing
        t:self_set_typing
        t:friend_get_typing
        t:friend_get_last_online
        """

        sSlot = 'friend_typing'
        LOG.info("test_typing_status bob adding alice")
        #: Test typing status
        def bob_on_friend_typing(iTox, fid:int, is_typing, *largs) -> None:
            LOG_INFO(f"BOB_ON_friend_typing is_typing={is_typing} fid={fid}")
            try:
                assert fid == self.baid
                if is_typing is True:
                    assert self.bob.friend_get_typing(fid) is True
            except Exception as e:
                LOG_ERROR(f"BOB_ON_friend_typing {e}")
            setattr(self.bob, sSlot, True)

        setattr(self.bob, sSlot, None)
        try:
            if self.bob._args.norequest:
                assert self.both_add_as_friend_norequest()
            else:
                assert self.both_add_as_friend()

            if not self.get_connection_status():
                LOG.warning(f"test_friend_typing NOT CONNECTED")
                self.loop_until_connected(self.bob)

            self.bob.callback_friend_typing(bob_on_friend_typing)
            self.warn_if_no_cb(self.bob, sSlot)
            self.alice.self_set_typing(self.abid, False)
            if not self.wait_otox_attrs(self.bob, [sSlot]):
                LOG_WARN(f"bobs_on_friend_typing NO {sSlot}")
        except AssertionError as e:
            LOG.error(f"Failed test {e}")
            raise
        except Exception as e:
            LOG.error(f"test_alice_typing_status error={e}")
            raise
        finally:
            self.bob.callback_friend_typing(None)
            if hasattr(self, 'baid') and self.baid >= 0:
                self.bob.friend_delete(self.baid)
            if hasattr(self, 'abid') and self.abid >= 0:
                self.alice.friend_delete(self.abid)

    @expectedFail('fails') # new name is empty
    def test_friend_name(self) -> None: # works!
        """
        t:self_set_name
        t:friend_get_name
        t:friend_get_name_size
        t:on_friend_name
        """

        sSlot= 'friend_name'
        #: Test friend request

        #: Test friend name
        NEWNAME = 'Jenny'

        def bobs_on_friend_name(iTox, fid:int, newname, iNameSize, *largs) -> None:
            LOG_INFO(f"bobs_on_friend_name {sSlot} {fid}")
            try:
                assert fid == self.baid
                assert str(newname, 'UTF-8') == NEWNAME
            except Exception as e:
                LOG_ERROR(f"bobs_on_friend_name EXCEPTION {e}")
            setattr(self.bob, sSlot, True)

        setattr(self.bob, sSlot, None)
        try:
            LOG.info("test_friend_name")
            if self.bob._args.norequest:
                assert self.bob_add_alice_as_friend_norequest()
            else:
                assert self.bob_add_alice_as_friend()
            if not self.get_connection_status():
                LOG.warning(f"test_friend_typing NOT CONNECTED")
                self.loop_until_connected(self.bob)

            self.bob.callback_friend_name(bobs_on_friend_name)
            self.warn_if_no_cb(self.bob, sSlot)
            self.alice.self_set_name(NEWNAME)
            if not self.wait_otox_attrs(self.bob, [sSlot]):
                LOG_WARN(f"bobs_on_friend_name NO {sSlot}")

            # name=None
            assert self.bob.friend_get_name(self.baid) == NEWNAME, \
              f"{self.bob.friend_get_name(self.baid)} != {NEWNAME}"
            assert self.bob.friend_get_name_size(self.baid) == len(NEWNAME), \
              f"{self.bob.friend_get_name_size(self.baid)} != {len(NEWNAME)}"

        except AssertionError as e:
            LOG.error(f"test_friend_name Failed test {e}")
            raise
        except Exception as e:
            LOG.error(f"test_friend EXCEPTION  {e}")
            raise
        finally:
            if hasattr(self, 'baid') and self.baid >= 0:
                self.bob.friend_delete(self.baid)
            self.bob.callback_friend_name(None)
            self.warn_if_cb(self.bob, sSlot)

#!    @expectedFail('fails')  # This client is currently not connected to the friend.
    def test_friend_message(self) -> None: # fails intermittently
        """
        t:on_friend_action
        t:on_friend_message
        t:friend_send_message
        """

       #: Test message
        MSG = 'Hi, Bob!'
        sSlot = 'friend_message'

        def alices_on_friend_message(iTox, fid:int, msg_type, message, iSize, *largs) -> None:
            LOG_DEBUG(f"alices_on_friend_message {fid} {message}")
            try:
                assert fid == self.alice.abid
                assert msg_type == TOX_MESSAGE_TYPE['NORMAL']
                assert str(message, 'UTF-8') == MSG
            except Exception as e:
                LOG_ERROR(f"alices_on_friend_message EXCEPTION {e}")
            else:
                LOG_INFO(f"alices_on_friend_message {message}")
            setattr(self.alice, sSlot, True)

        setattr(self.alice, sSlot, None)
        self.alice.callback_friend_message(None)
        try:
            if self.bob._args.norequest:
                assert self.both_add_as_friend_norequest()
            else:
                assert self.both_add_as_friend()
            assert hasattr(self, 'baid'), \
              "both_add_as_friend_norequest no bob, baid"
            assert hasattr(self, 'abid'), \
              "both_add_as_friend_norequest no alice, abid"
            if not self.wait_friend_get_connection_status(self.bob, self.baid, n=2*iN):
                LOG.warn('baid not connected')
            if not self.wait_friend_get_connection_status(self.alice, self.abid, n=2*iN):
                LOG.warn('abid not connected')
            self.alice.callback_friend_message(alices_on_friend_message)
            self.warn_if_no_cb(self.alice, sSlot)

            # dunno - both This client is currently NOT CONNECTED to the friend.
            iMesId = self.bob.friend_send_message(self.baid,
                                                  TOX_MESSAGE_TYPE['NORMAL'],
                                                  bytes(MSG, 'UTF-8'))
            assert iMesId >= 0, "iMesId >= 0"
            if not self.wait_otox_attrs(self.alice, [sSlot]):
                LOG_WARN(f"alices_on_friend_message NO {sSlot}")
        except ArgumentError as e:
            #  ArgumentError('This client is currently NOT CONNECTED to the friend.')
            # dunno
            LOG.error(f"test_friend_message ArgumentError {e}")
            raise
        except AssertionError as e:
            LOG.error(f"test_friend_message AssertionError {e}")
            raise
        except Exception as e:
            LOG.error(f"test_friend_message EXCEPTION {e}")
            raise
        finally:
            self.alice.callback_friend_message(None)
            self.warn_if_cb(self.alice, sSlot)
            if hasattr(self, 'baid') and self.baid >= 0:
                self.bob.friend_delete(self.baid)
            if hasattr(self, 'abid') and self.abid >= 0:
                self.alice.friend_delete(self.abid)

    # This client is currently not connected to the friend.
    def test_friend_action(self) -> None: # works! sometimes?
        """
        t:on_friend_action
        t:on_friend_message
        t:friend_send_message
        """

        #: Test action
        ACTION = 'Kick'
        sSlot = 'friend_read_action'
        setattr(self.bob, sSlot, None)
        def UNUSEDtheir_on_friend_action(iTox, fid:int, msg_type, action, *largs):
            LOG_DEBUG(f"their_on_friend_action {fid} {msg_type} {sSlot} {action}")
            try:
                assert msg_type == TOX_MESSAGE_TYPE['ACTION']
                assert action == ACTION
            except Exception as e:
                LOG_ERROR(f"their_on_friend_action EXCEPTION {sSlot} {e}")
            else:
                LOG_INFO(f"their_on_friend_action {sSlot} {action}")
            setattr(self.bob, sSlot, True)

        sSlot = 'friend_read_receipt'
        setattr(self.alice, sSlot, None)
        def their_on_read_reciept(iTox, fid:int, msg_id, *largs) -> None:
            LOG_DEBUG(f"their_on_read_reciept {fid} {msg_id}")
            sSlot = 'friend_read_receipt'
            try:
                # should be the receivers id
                if hasattr(bob, 'baid'):
                    assert fid == bob.baid
                    setattr(self.bob, sSlot, True)
                elif hasattr(alice, 'abid'):
                    assert fid == alice.abid
                    setattr(self.alice, sSlot, True)
                assert msg_id >= 0
            except Exception as e:
                LOG_ERROR(f"their_on_read_reciept {sSlot} {e}")
            else:
                LOG_INFO(f"their_on_read_reciept {sSlot} fid={fid}")

        try:
            if self.bob._args.norequest:
                assert self.both_add_as_friend_norequest()
            else:
                assert self.both_add_as_friend()

            if not self.wait_friend_get_connection_status(self.bob, self.baid, n=iN):
                LOG.warn('baid not connected')
            if not self.wait_friend_get_connection_status(self.alice, self.abid, n=iN):
                LOG.warn('abid not connected')

            self.bob.callback_friend_read_receipt(their_on_read_reciept) #was their_on_friend_action
            self.alice.callback_friend_read_receipt(their_on_read_reciept) #was their_on_friend_action
            self.warn_if_no_cb(self.bob, 'friend_read_receipt')
            self.warn_if_no_cb(self.alice, 'friend_read_receipt')
            if True:
                iMsg = self.bob.friend_send_message(self.baid,
                                                TOX_MESSAGE_TYPE['ACTION'],
                                                bytes(ACTION, 'UTF-8'))
                assert iMsg >= 0
            else:
                assert self.wait_ensure_exec(self.bob.friend_send_message,
                                             [self.baid,
                                              TOX_MESSAGE_TYPE['ACTION'],
                                              bytes(ACTION, 'UTF-8')])
            if not self.wait_otox_attrs(self.alice, [sSlot]):
                LOG_WARN(f"alice test_friend_action NO {sSlot}")
        except AssertionError as e:
            LOG.error(f"Failed test {e}")
            raise
        except ArgumentError as e:
            #  ArgumentError('This client is currently NOT CONNECTED to the friend.')
            # dunno
            LOG.warning(f"test_friend_action  {e}")
        except Exception as e:
            LOG.error(f"test_friend_action  {e}")
            raise
        finally:
            self.alice.callback_friend_read_receipt(None)
            if hasattr(self, 'baid') and self.baid >= 0:
                self.bob.friend_delete(self.baid)
            if hasattr(self, 'abid') and self.abid >= 0:
                self.alice.friend_delete(self.abid)

    @expectedFail('fails')  #     @unittest.skip('unfinished')
    def test_file_transfer(self) -> None: # unfinished
        """
        t:file_send
        t:file_send_chunk
        t:file_control
        t:file_seek
        t:file_get_file_id
        t:on_file_recv
        t:on_file_recv_control
        t:on_file_recv_chunk
        t:on_file_chunk_request
        """

        if self.bob._args.norequest:
            assert self.both_add_as_friend_norequest()
        else:
            assert self.both_add_as_friend()

        FILE_NUMBER = 1
        FILE = os.urandom(1024 * 1024)
        FILE_NAME = b"/tmp/test.bin"
        if not os.path.exists(FILE_NAME):
            with open(FILE_NAME, 'wb') as oFd:
                oFd.write(FILE)
        FILE_SIZE = len(FILE)
        OFFSET = 567
        # was FILE_ID = FILE_NAME
        FILE_ID = 32*'1' #

        m = hashlib.md5()
        m.update(FILE[OFFSET:])
        FILE_DIGEST = m.hexdigest()

        CONTEXT = { 'FILE': bytes(), 'RECEIVED': 0, 'START': False, 'SENT': 0 }

        def alice_on_file_recv(iTox, fid:int, file_number:int, kind, size, filename) -> None:
            LOG_DEBUG(f"ALICE_ON_file_recv fid={fid} {file_number}")
            try:
                assert size == FILE_SIZE
                assert filename == FILE_NAME
                retv = self.alice.file_seek(fid, file_number, OFFSET)
                assert retv is True
                self.alice.file_control(fid, file_number, TOX_FILE_CONTROL['RESUME'])
            except Exception as e:
                LOG_ERROR(f"ALICE_ON_file_recv  {e}")
            else:
                LOG_INFO(f"ALICE_ON_file_recv " + str(fid))

        def alice_on_file_recv_control(iTox, fid:int, file_number, control, *largs) -> None:
            # TOX_FILE_CONTROL = {    'RESUME': 0,    'PAUSE': 1,    'CANCEL': 2,}
            LOG_DEBUG(f"ALICE_ON_file_recv_control fid={fid} {file_number} {control}")
            try:
                assert FILE_NUMBER == file_number
                # FixMe _FINISHED?
                if False and control == TOX_FILE_CONTROL['RESUME']:
                    #         assert CONTEXT['RECEIVED'] == FILE_SIZE
                    #         m = hashlib.md5()
                    #         m.update(CONTEXT['FILE'])
                    #         assert m.hexdigest() == FILE_DIGEST
                    self.alice.completed = True
            except Exception as e:
                LOG_ERROR(f"ALICE_ON_file_recv  {e}")
            else:
                LOG_INFO(f"ALICE_ON_file_recv " + str(fid))

        self.alice.completed = False
        def alice_on_file_recv_chunk(iTox, fid:int, file_number:int, position:int, iNumBytes, *largs) -> bool:
            LOG_DEBUG(f"ALICE_ON_file_recv_chunk {fid} {file_number}")
            # FixMe - use file_number and iNumBytes to get data?
            data = ''
            LOG_INFO(f"ALICE_ON_file_recv_chunk {fid}")
            try:
                if data is None:
                    assert CONTEXT['RECEIVED'] == (FILE_SIZE - OFFSET)
                    m = hashlib.md5()
                    m.update(CONTEXT['FILE'])
                    assert m.hexdigest() == FILE_DIGEST
                    self.alice.completed = True
                    self.alice.file_control(fid, file_number, TOX_FILE_CONTROL['CANCEL'])
                    return True

                CONTEXT['FILE'] += data
                CONTEXT['RECEIVED'] += len(data)
                # if CONTEXT['RECEIVED'] < FILE_SIZE:
                #    assert self.file_data_remaining(
                #        fid, file_number, 1) == FILE_SIZE - CONTEXT['RECEIVED']
            except Exception as e:
                LOG_ERROR(f"ALICE_ON_file_recv_chunk {e}")
                return False
            return True

        # AliceTox.on_file_send_request = on_file_send_request
        # AliceTox.on_file_control = on_file_control
        # AliceTox.on_file_data = on_file_data

        try:
            # required?
            if not self.wait_friend_get_connection_status(self.bob, self.baid, n=2*iN):
                LOG_WARN(f"bobs wait_friend_get_connection_status {2*iN}")

            if not self.wait_friend_get_connection_status(self.alice, self.abid, n=2*iN):
                LOG_WARN(f"alices' wait_friend_get_connection_status {2*iN}")

            self.alice.callback_file_recv(alice_on_file_recv)
            self.alice.callback_file_recv_control(alice_on_file_recv_control)
            self.alice.callback_file_recv_chunk(alice_on_file_recv_chunk)

            self.bob.completed = False
            def bob_on_file_recv_control2(iTox, fid:int, file_number:int, control) -> None:
                LOG_DEBUG(f"BOB_ON_file_recv_control2 {fid} {file_number} control={control}")
                if control == TOX_FILE_CONTROL['RESUME']:
                    CONTEXT['START'] = True
                elif control == TOX_FILE_CONTROL['CANCEL']:
                    self.bob.completed = True
                    pass

            def bob_on_file_chunk_request(iTox, fid:int, file_number:int, position:int, length, *largs) -> None:
                LOG_DEBUG(f"BOB_ON_file_chunk_request {fid} {file_number}")
                if length == 0:
                    return
                data = FILE[position:(position + length)]
                self.bob.file_send_chunk(fid, file_number, position, data)

            sSlot = 'file_recv_control'
            self.bob.callback_file_recv_control(bob_on_file_recv_control2)
            self.bob.callback_file_chunk_request(bob_on_file_chunk_request)

            i = 0
            iKind = 0
            while i < 2:
                i += 1
                try:
                    FN = self.bob.file_send(self.baid, iKind, FILE_SIZE, FILE_ID, FILE_NAME)
                    LOG.info(f"test_file_transfer bob.file_send {FN}")
                except ArgumentError as e:
                    LOG.debug(f"test_file_transfer bob.file_send {e} {i}")
                    # ctypes.ArgumentError: This client is currently not connected to the friend
                    raise
                else:
                    break
                self.loop(100)
                sleep(1)
            else:
                LOG.error(f"test_file_transfer bob.file_send 2")
                raise AssertionError(f"test_file_transfer bob.file_send {self.bob._args.test_timeout // 2}")

            # UINT32_MAX
            try:
                FID = self.bob.file_get_file_id(self.baid, FN)
                hexFID = "".join([hex(ord(c))[2:].zfill(2) for c in FILE_NAME])
                assert FID.startswith(hexFID.upper())
            except Exception as e:
                LOG.warn(f"test_file_transfer:: {FILE_NAME} {hexFID} {e}")
                LOG.debug('\n' + traceback.format_exc())

            if not self.wait_otox_attrs(self.bob, ['completed']):
                LOG_WARN(f"test_file_transfer Bob NO completed")
                return False
            if not self.wait_otox_attrs(self.alice, ['completed']):
                LOG_WARN(f"test_file_transfer Alice NO completed")
                return False
            return True

        except (ArgumentError, ValueError,) as e:
               # ValueError: non-hexadecimal number found in fromhex() arg at position 0
               LOG.error(f"test_file_transfer: {e}")
               raise

        except Exception as e:
               LOG.error(f"test_file_transfer:: {e}")
               LOG.debug('\n' + traceback.format_exc())
               raise

        finally:
            self.alice.callback_file_recv(None)
            self.alice.callback_file_recv_control(None)
            self.alice.callback_file_recv_chunk(None)
            self.bob.callback_file_recv_control(None)
            self.bob.callback_file_chunk_request(None)
            if hasattr(self, 'baid') and self.baid >= 0:
                self.bob.friend_delete(self.baid)
            if hasattr(self, 'abid') and self.abid >= 0:
                self.alice.friend_delete(self.abid)

            LOG_INFO(f"test_file_transfer:: self.wait_objs_attr completed")

    @unittest.skip('crashes')
    def test_tox_savedata(self) -> None: #
        """
        t:get_savedata_size
        t:get_savedata
        """
        # Fatal Python error: Aborted
        # "/var/local/src/toxygen_wrapper/wrapper/tox.py", line 180 in kill
        global oTOX_OARGS

        assert self.alice.get_savedata_size() > 0
        data = self.alice.get_savedata()
        assert data is not None
        addr = self.alice.self_get_address()
        # self._address

        try:
            LOG.info("test_tox_savedata alice.kill")
            # crashes
            self.alice.kill()
            del self.alice
        except:
            pass

        oArgs = oTOX_OARGS
        opts = oTestsToxOptions(oArgs)
        opts.savedata_data = data
        opts.savedata_length = len(data)

        self.alice = Tox(tox_options=opts)
        if addr != self.alice.self_get_address():
            LOG.warning("test_tox_savedata " +
                      f"{addr} != {self.alice.self_get_address()}")
        else:
            LOG.info("passed test_tox_savedata")

    def test_kill(self) -> None: #
        import threading
        LOG.info(f"THE END {threading.active_count()}")
        self.tearDown()
        LOG.info(f"THE END {threading.enumerate()}")


def vOargsToxPreamble(oArgs, Tox, ToxTest) -> None:

    ts.vSetupLogging(oArgs)

    methods = set([x for x in dir(Tox) if not x[0].isupper()
                   and not x[0] == '_'])
    docs = "".join([getattr(ToxTest, x).__doc__ for x in dir(ToxTest)
                    if getattr(ToxTest, x).__doc__ is not None])

    tested = set(re.findall(r't:(.*?)\n', docs))
    not_tested = methods.difference(tested)

    logging.info('Test Coverage: %.2f%%' % (len(tested) * 100.0 / len(methods)))
    if len(not_tested):
        logging.info('Not tested:\n    %s' % "\n    ".join(sorted(list(not_tested))))


###

def iMain(oArgs, failfast=True) -> int:

#    collect_types.init_types_collection()

    vOargsToxPreamble(oArgs, Tox, ToxSuite)
    # https://stackoverflow.com/questions/35930811/how-to-sort-unittest-testcases-properly/35930812#35930812
    cases = ts.suiteFactory(*ts.caseFactory([ToxSuite]))
    if color_runner:
        runner = color_runner.runner.TextTestRunner(verbosity=2, failfast=failfast)
    else:
        runner = unittest.TextTestRunner(verbosity=2, failfast=failfast, warnings='ignore')

#    with collect_types.collect():
    runner.run(cases)
 #   collect_types.dump_stats('tests_wrapper.out')

def oTestsToxOptions(oArgs):
    data = None
    tox_options = tox_wrapper.tox.Tox.options_new()
    if oArgs.proxy_type:
        tox_options.contents.proxy_type = int(oArgs.proxy_type)
        tox_options.contents.proxy_host = bytes(oArgs.proxy_host, 'UTF-8')
        tox_options.contents.proxy_port = int(oArgs.proxy_port)
        tox_options.contents.udp_enabled = oArgs.udp_enabled = False
    else:
        tox_options.contents.udp_enabled = oArgs.udp_enabled
    if not os.path.exists('/proc/sys/net/ipv6'):
        oArgs.ipv6_enabled = False
    else:
        tox_options.contents.ipv6_enabled = oArgs.ipv6_enabled

    tox_options.contents.tcp_port = int(oArgs.tcp_port)
    tox_options.contents.dht_announcements_enabled = oArgs.dht_announcements_enabled
    tox_options.contents.hole_punching_enabled = oArgs.hole_punching_enabled

    # overrides
    tox_options.contents.local_discovery_enabled = False
    tox_options.contents.experimental_thread_safety = False
    # REQUIRED!!
    if oArgs.ipv6_enabled and not os.path.exists('/proc/sys/net/ipv6'):
        LOG.warning('Disabling IPV6 because /proc/sys/net/ipv6 does not exist' + repr(oArgs.ipv6_enabled))
        tox_options.contents.ipv6_enabled = False
    else:
        tox_options.contents.ipv6_enabled = bool(oArgs.ipv6_enabled)

    if data:  # load existing profile
        tox_options.contents.savedata_type = enums.TOX_SAVEDATA_TYPE['TOX_SAVE']
        tox_options.contents.savedata_data = c_char_p(data)
        tox_options.contents.savedata_length = len(data)
    else:  # create new profile
        tox_options.contents.savedata_type = enums.TOX_SAVEDATA_TYPE['NONE']
        tox_options.contents.savedata_data = None
        tox_options.contents.savedata_length = 0

    return tox_options

def oArgparse(lArgv):
    global THRESHOLD
    parser = ts.oMainArgparser()
    parser.add_argument('--norequest',type=str, default='False',
                        choices=['True','False'],
                        help='Use _norequest during testing')
    parser.add_argument('--test_timeout',type=int, default=THRESHOLD,
                        help='Test timeout during testing')
    parser.add_argument('profile', type=str, nargs='?', default=None,
                        help='Path to Tox profile')
    oArgs = parser.parse_args(lArgv)
    ts.clean_booleans(oArgs)
    THRESHOLD = oArgs.test_timeout

    if hasattr(oArgs, 'sleep'):
        if oArgs.sleep == 'qt':
            pass # broken or gevent.sleep(idle_period)
        elif oArgs.sleep == 'gevent':
            pass # broken or gevent.sleep(idle_period)
        else:
            oArgs.sleep = 'time'

    return oArgs

def main(lArgs=None) -> int:
    global     oTOX_OARGS
    global bIS_LOCAL
    global THRESHOLD
    if lArgs is None: lArgs = sys.argv[1:]
    oArgs = oArgparse(lArgs)
    bIS_LOCAL = oArgs.network in ['newlocal', 'localnew', 'local']
    THRESHOLD = oArgs.test_timeout

    oTOX_OARGS = oArgs
    setattr(oTOX_OARGS, 'bIS_LOCAL', bIS_LOCAL)
    bIS_LOCAL = True
    setattr(oTOX_OARGS, 'bIS_LOCAL', bIS_LOCAL)
    # oTOX_OPTIONS = ToxOptions()
    global oTOX_OPTIONS
    oTOX_OPTIONS = oTestsToxOptions(oArgs)
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
    sys.exit(main(sys.argv[1:] ))
