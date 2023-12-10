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

Modified to work with
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

faulthandler.enable()

import warnings

warnings.filterwarnings('ignore')

try:
    from io import BytesIO

    import certifi
    import pycurl
except ImportError:
    pycurl = None

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

import wrapper
import wrapper.toxcore_enums_and_consts as enums
from wrapper.tox import Tox, UINT32_MAX, ToxError

from wrapper.toxcore_enums_and_consts import (TOX_ADDRESS_SIZE, TOX_CONNECTION,
                                              TOX_FILE_CONTROL,
                                              TOX_MESSAGE_TYPE,
                                              TOX_SECRET_KEY_SIZE,
                                              TOX_USER_STATUS)

try:
    import support_testing as ts
except ImportError:
    import wrapper_tests.support_testing as ts

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
    def LOG_ERROR(l): LOG.error('+ '+l)
    def LOG_WARN(l): LOG.warn('+ '+l)
    def LOG_INFO(l): LOG.info('+ '+l)
    def LOG_DEBUG(l): LOG.debug('+ '+l)
    def LOG_TRACE(l): pass # print('+ '+l)
else:
    # just print to stdout so there is NO complications from logging.
    def LOG_ERROR(l): print('EROR+ '+l)
    def LOG_WARN(l): print('WARN+ '+l)
    def LOG_INFO(l): print('INFO+ '+l)
    def LOG_DEBUG(l): print('DEBUG+ '+l)
    def LOG_TRACE(l): pass # print('TRAC+ '+l)

ADDR_SIZE = 38 * 2
CLIENT_ID_SIZE = 32 * 2
THRESHOLD = 30 # >25
iN = 6

global     oTOX_OPTIONS
oTOX_OPTIONS = {}

bIS_LOCAL = 'new' in sys.argv or 'local' in sys.argv or 'newlocal' in sys.argv
bUSE_NOREQUEST = None

def expectedFailure(test_item):
    test_item.__unittest_expecting_failure__ = True
    return test_item

def expectedFail(reason):
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

    def __init__(self, opts, app=None):

        super(AliceTox, self).__init__(opts, app=app)
        self._address = self.self_get_address()
        self.name = 'alice'
        self._opts = opts
        self._app = app

class BobTox(Tox):

    def __init__(self, opts, app=None):
        super(BobTox, self).__init__(opts, app=app)
        self._address = self.self_get_address()
        self.name = 'bob'
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

    def stop_thread(self, timeout=-1):
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

    def run(self):
        while not self._stop_thread:
            self._tox.iterate()
            sleep(self._tox.iteration_interval() / 1000)

global bob, alice
bob = alice = None

def prepare(self):
    global bob, alice
    def bobs_on_self_connection_status(iTox, connection_state, *args):
        status = connection_state
        self.bob.dht_connected = status
        self.bob.mycon_time = time.time()
        try:
            if status != TOX_CONNECTION['NONE']:
                LOG_DEBUG(f"bobs_on_self_connection_status TRUE {status}" \
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

    def alices_on_self_connection_status(iTox, connection_state, *args):
        #FixMe connection_num
        status = connection_state
        self.alice.dht_connected = status
        self.alice.mycon_time = time.time()
        try:
            if status != TOX_CONNECTION['NONE']:
                LOG_DEBUG(f"alices_on_self_connection_status TRUE {status}" \
                          +f" last={int(self.alice.mycon_time)}" )
                self.alice.mycon_status = True
            else:
                LOG_WARN(f"alices_on_self_connection_status FALSE {status}" \
                          +f" last={int(self.alice.mycon_time)}" )
                self.alice.mycon_status = False
        except Exception as e:
            LOG_ERROR(f"alices_on_self_connection_status error={e}")
        self.alice.dht_connected = status

    opts = oToxygenToxOptions(oTOX_OARGS)
    global bUSE_NOREQUEST
    bUSE_NOREQUEST = oTOX_OARGS.norequest == 'True'

    alice = AliceTox(opts, app=oAPP)
    alice.oArgs = opts
    alice.dht_connected = -1
    alice.mycon_status = False
    alice.mycon_time = 1
    alice.callback_self_connection_status(alices_on_self_connection_status)

    bob = BobTox(opts, app=oAPP)
    bob.oArgs = opts
    bob.dht_connected = -1
    bob.mycon_status = False
    bob.mycon_time = 1
    bob.callback_self_connection_status(bobs_on_self_connection_status)
    if not bIS_LOCAL and not ts.bAreWeConnected():
        LOG.warning(f"doOnce not local and NOT CONNECTED")
    return [bob, alice]

class ToxSuite(unittest.TestCase):
    failureException = AssertionError

    @classmethod
    def setUpClass(cls):
        global oTOX_OARGS
        assert oTOX_OPTIONS
        assert oTOX_OARGS

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

    def tearDown(self):
        """
        """
        if hasattr(self, 'bob') and self.bob.self_get_friend_list_size() >= 1:
            LOG.warn(f"tearDown BOBS STILL HAS A FRIEND LIST {self.bob.self_get_friend_list()}")
            for elt in self.bob.self_get_friend_list(): self.bob.friend_delete(elt)
        if hasattr(self, 'alice') and self.alice.self_get_friend_list_size() >= 1:
            LOG.warn(f"tearDown ALICE STILL HAS A FRIEND LIST {self.alice.self_get_friend_list()}")
            for elt in self.alice.self_get_friend_list(): self.alice.friend_delete(elt)

        LOG.debug(f"tearDown threads={threading.active_count()}")
        if hasattr(self, 'bob'):
            bob.callback_self_connection_status(None)
            if hasattr(self.bob, 'main_loop'):
                self.bob._main_loop.stop_thread()
                del self.bob._main_loop
#            self.bob.kill()
            del         self.bob
        if hasattr(self, 'alice'):
            alice.callback_self_connection_status(None)
            if hasattr(self.alice, 'main_loop'):
                self.alice._main_loop.stop_thread()
                del self.alice._main_loop
#            self.alice.kill()
            del         self.alice

    @classmethod
    def tearDownClass(cls):
        if hasattr(cls, 'bob'):
            cls.bob._main_loop.stop_thread()
            cls.bob.kill()
            del         cls.bob
        if hasattr(cls, 'alice'):
            cls.alice._main_loop.stop_thread()
            cls.alice.kill()
            del         cls.alice

    def bBobNeedAlice(self):
        """
        """
        if hasattr(self, 'baid') and self.baid >= 0 and \
          self.baid in self.bob.self_get_friend_list():
            LOG.warn(f"setUp ALICE IS ALREADY IN BOBS FRIEND LIST")
            return False
        elif self.bob.self_get_friend_list_size() >= 1:
            LOG.warn(f"setUp BOB STILL HAS A FRIEND LIST")
            return False
        return True

    def bAliceNeedAddBob (self):
        if hasattr(self, 'abid') and self.abid >= 0 and \
          self.abid in self.alice.self_get_friend_list():
            LOG.warn(f"setUp BOB IS ALREADY IN ALICES FRIEND LIST")
            return False
        elif self.alice.self_get_friend_list_size() >= 1:
            LOG.warn(f"setUp ALICE STILL HAS A FRIEND LIST")
            return False
        return True

    def setUp(self):
        cls = self
        if not hasattr(cls, 'alice') and not hasattr(cls, 'bob'):
            l = prepare(cls)
            assert l
            cls.bob, cls.alice = l
        if not hasattr(cls.bob, '_main_loop'):
#?            cls.bob._main_loop = ToxIterateThread(cls.bob)
#?            cls.bob._main_loop.start()
            LOG.debug(f"cls.bob._main_loop: ") # {threading.enumerate()}
        if not hasattr(cls.alice, '_main_loop'):
#?            cls.alice._main_loop = ToxIterateThread(cls.alice)
#?            cls.alice._main_loop.start()
            LOG.debug(f"cls.alice._main_loop: ") # {threading.enumerate()}

        self.bBobNeedAlice()
        self.bAliceNeedAddBob()

    def run(self, result=None):
        """ Stop after first error """
        if not result.errors:
            super(ToxSuite, self).run(result)

    def get_connection_status(self):
        if self.bob.mycon_time <= 1 or self.alice.mycon_time <= 1:
            pass
            # drop through
        elif self.bob.dht_connected == TOX_CONNECTION['NONE']:
            return False
        elif self.alice.dht_connected == TOX_CONNECTION['NONE']:
            return False

        # if not self.connected
        if self.bob.self_get_connection_status() == TOX_CONNECTION['NONE']:
            return False
        if self.alice.self_get_connection_status() == TOX_CONNECTION['NONE']:
            return False
        return True

    def loop(self, n):
        """
        t:iterate
        t:iteration_interval
        """
        interval = self.bob.iteration_interval()
        for i in range(n):
            self.alice.iterate()
            self.bob.iterate()
            sleep(interval / 1000.0)

    def call_bootstrap(self, num=None, lToxes=None, i=0):
        if num == None: num=ts.iNODES
        if lToxes is None:
            lToxes = [self.alice, self.bob]
#        LOG.debug(f"call_bootstrap network={oTOX_OARGS.network}")
        if oTOX_OARGS.network in ['new', 'newlocal', 'localnew']:
            ts.bootstrap_local(self.lUdp, lToxes)
        elif not ts.bAreWeConnected():
            LOG.warning('we are NOT CONNECTED')
        else:
            random.shuffle(self.lUdp)
            if oTOX_OARGS.proxy_port > 0:
                lElts = self.lUdp[:1]
            else:
                lElts = self.lUdp[:num+i]
            LOG.debug(f"call_bootstrap ts.bootstrap_udp {len(lElts)}")
            ts.bootstrap_udp(lElts, lToxes)
            random.shuffle(self.lTcp)
            lElts = self.lTcp[:num+i]
            LOG.debug(f"call_bootstrap ts.bootstrap_tcp {len(lElts)}")
            ts.bootstrap_tcp(lElts, lToxes)

    def group_until_connected(self, otox, group_number, num=None, iMax=THRESHOLD):
        """
        """
        i = 0
        bRet = None
        while i <= iMax :
            iRet = otox.group_is_connected(group_number)
            if iRet == True or iRet == 0:
                bRet = True
                break
            if i % 5 == 0:
                j = i//5
                self.call_bootstrap(num, lToxes=None, i=j)
                s = ''
                if i == 0: s = '\n'
                LOG.info(s+"group_until_connected " \
                         +" #" + str(i) \
                         +" iRet=" +repr(iRet) \
                         +f" BOBS={otox.mycon_status}" \
                         +f" last={int(otox.mycon_time)}" )
            i += 1
            self.loop(100)
        else:
            bRet = False

        if bRet:
            LOG.info(f"group_until_connected True i={i}" \
                     +f" iMax={iMax}" \
                     +f" BOB={otox.self_get_connection_status()}" \
                     +f" last={int(otox.mycon_time)}" )
            return True
        else:
            LOG.warning(f"group_until_connected False i={i}" \
                        +f" iMax={iMax}" \
                        +f" BOB={otox.self_get_connection_status()}" \
                        +f" last={int(otox.mycon_time)}" )
            return False

    def loop_until_connected(self, num=None):
        """
        t:on_self_connection_status
        t:self_get_connection_status
        """
        global  THRESHOLD
        i = 0
        bRet = None
        while i <= THRESHOLD :
            if (self.alice.mycon_status and self.bob.mycon_status):
                bRet = True
                break
            if i % 5 == 0:
                j = i//5
                self.call_bootstrap(num, lToxes=None, i=j)
                s = ''
                if i == 0: s = '\n'
                LOG.info(s+"loop_until_connected " \
                         +" #" + str(i) \
                         +" BOB=" +repr(self.bob.self_get_connection_status()) \
                         +" ALICE=" +repr(self.alice.self_get_connection_status())
                         +f" BOBS={self.bob.mycon_status}" \
                         +f" ALICES={self.alice.mycon_status}" \
                         +f" last={int(self.bob.mycon_time)}" )
            if (self.alice.mycon_status and self.bob.mycon_status):
                bRet = True
                break
            if (self.alice.self_get_connection_status() and
                self.bob.self_get_connection_status()):
                LOG_WARN(f"loop_until_connected disagree status() DISAGREE" \
                         +f' self.bob.mycon_status={self.bob.mycon_status}' \
                         +f' alice.mycon_status={self.alice.mycon_status}' \
                         +f" last={int(self.bob.mycon_time)}" )
                bRet = True
                break
            i += 1
            self.loop(100)
        else:
            bRet = False

        if bRet or \
            ( self.bob.self_get_connection_status() != TOX_CONNECTION['NONE'] and \
              self.alice.self_get_connection_status() != TOX_CONNECTION['NONE'] ):
            LOG.info(f"loop_until_connected returning True {i}" \
                     +f" BOB={self.bob.self_get_connection_status()}" \
                     +f" ALICE={self.alice.self_get_connection_status()}" \
                     +f" last={int(self.bob.mycon_time)}" )
            return True
        else:
            THRESHOLD += 5
            LOG.warning(f"loop_until_connected returning False {i}" \
                     +f" BOB={self.bob.self_get_connection_status()}" \
                     +f" ALICE={self.alice.self_get_connection_status()}" \
                     +f" last={int(self.bob.mycon_time)}" )
            return False

    def wait_objs_attr(self, objs, attr):
        global  THRESHOLD
        i = 0
        while i <= THRESHOLD:
            if i % 5 == 0:
                num = None
                j = 0
                j = i//5
                self.call_bootstrap(num, objs, i=j)
                LOG.debug(f"wait_objs_attr {objs} for {attr} {i}")
            if all([getattr(obj, attr) for obj in objs]):
                return True
            self.loop(100)
            i += 1
        else:
            THRESHOLD += 1
            LOG.warn(f"wait_objs_attr for {attr} i >= {THRESHOLD}")

        return all([getattr(obj, attr) is not None for obj in objs])

    def wait_otox_attrs(self, obj, attrs):
        assert all(attrs), f"wait_otox_attrs {attrs}"
        i = 0
        while i <= THRESHOLD:
            if i % 5 == 0:
                num = None
                j = 0
                if obj.mycon_time == 1:
                    num = 4
                    j = i//5
                if obj.self_get_connection_status() == TOX_CONNECTION['NONE']:
                    self.call_bootstrap(num, [obj], i=j)
                LOG.debug(f"wait_otox_attrs {obj.name} for {attrs} {i}" \
                         +f" last={int(obj.mycon_time)}")
            if all([getattr(obj, attr) is not None for attr in attrs]):
                return True
            self.loop(100)
            i += 1
        else:
            LOG.warning(f"wait_otox_attrs i >= {THRESHOLD} results={[getattr(obj, attr) for attr in attrs]}")

        return all([getattr(obj, attr) for attr in attrs])

    def wait_ensure_exec(self, method, args):
        i = 0
        oRet = None
        while i <= THRESHOLD:
            if i % 5 == 0:
                j = i//5
                self.call_bootstrap(num=None, lToxes=None, i=j)
                LOG.debug("wait_ensure_exec " \
                             +" " +str(method)
                             +" " +str(i))
            try:
                oRet = method(*args)
                if oRet:
                    LOG.info(f"wait_ensure_exec oRet {oRet!r}")
                    return True
            except ArgumentError as e:
                #  ArgumentError('This client is currently NOT CONNECTED to the friend.')
                # dunno
                LOG.warning(f"wait_ensure_exec ArgumentError {e}")
                return False
            except Exception as e:
                LOG.warning(f"wait_ensure_exec EXCEPTION  {e}")
                return False
            sleep(3)
            i += 1
        else:
            LOG.error(f"wait_ensure_exec i >=  {1*THRESHOLD}")
            return False

        return oRet

    def bob_add_alice_as_friend_norequest(self):
        if not self.bBobNeedAlice(): return True

        MSG = 'Hi, this is Bob.'
        iRet = self.bob.friend_add_norequest(self.alice._address)
        if iRet < 0:
            return False
        self.baid = self.bob.friend_by_public_key(self.alice._address)
        assert self.baid >= 0, self.baid
        assert self.bob.friend_exists(self.baid), "bob.friend_exists"
        assert not self.bob.friend_exists(self.baid + 1)
        assert self.baid in self.bob.self_get_friend_list()
        assert self.bob.self_get_friend_list_size() >= 1
        return True

    def alice_add_bob_as_friend_norequest(self):
        if not self.bAliceNeedAddBob(): return True

        iRet = self.alice.friend_add_norequest(self.bob._address)
        if iRet < 0:
            return False
        self.abid = self.alice.friend_by_public_key(self.bob._address)
        assert self.abid >= 0, self.abid
        assert self.abid in self.alice.self_get_friend_list()
        assert self.alice.friend_exists(self.abid), "alice.friend_exists"
        assert not self.alice.friend_exists(self.abid + 1)
        assert self.alice.self_get_friend_list_size() >= 1
        return True

    def both_add_as_friend(self):
        if bUSE_NOREQUEST:
            assert self.bob_add_alice_as_friend()
            assert self.alice_add_bob_as_friend_norequest()
        else:
            assert self.bob_add_alice_as_friend_norequest()
            assert self.alice_add_bob_as_friend_norequest()
        if not hasattr(self, 'baid') or self.baid < 0:
            LOG.warn("both_add_as_friend no bob, baid")
        if not hasattr(self, 'abid') or self.abid < 0:
            LOG.warn("both_add_as_friend no alice, abid")
        return True

    def both_add_as_friend_norequest(self):
        if self.bBobNeedAlice():
            assert self.bob_add_alice_as_friend_norequest()
        if self.bAliceNeedAddBob():
            assert self.alice_add_bob_as_friend_norequest()
        if not hasattr(self, 'baid') or self.baid < 0:
            LOG.warn("both_add_as_friend_norequest no bob, baid")
        if not hasattr(self, 'abid') or self.abid < 0:
            LOG.warn("both_add_as_friend_norequest no alice, abid")

        #: Test last online
#?        assert self.alice.friend_get_last_online(self.abid) is not None
#?        assert self.bob.friend_get_last_online(self.baid) is not None
        return True

    def bob_add_alice_as_friend(self):
        """
        t:friend_add
        t:on_friend_request
        t:friend_by_public_key
        """
        MSG = 'Alice, this is Bob.'
        sSlot = 'friend_request'
        if not self.bBobNeedAlice(): return True

        def alices_on_friend_request(iTox,
                                     public_key,
                                     message_data,
                                     message_data_size,
                                     *largs):
            LOG_DEBUG(f"alices_on_friend_request: " +repr(message_data))
            try:
                assert str(message_data, 'UTF-8') == MSG
                LOG_INFO(f"alices_on_friend_request: friend_added = True ")
            except Exception as e:
                LOG_WARN(f"alices_on_friend_request: Exception  {e}")
                # return
            setattr(self.bob, sSlot, True)

        setattr(self.bob, sSlot, None)
        inum = -1
        try:
            inum = self.bob.friend_add(self.alice._address, bytes(MSG, 'UTF-8'))
            assert inum >= 0, f"bob.friend_add !>= 0 {inum}"
            self.alice.callback_friend_request(alices_on_friend_request)
            if not self.wait_otox_attrs(self.bob, [sSlot]):
                LOG_WARN(f"bob.friend_add NO {sSlot}")
                # return False
            self.baid = self.bob.friend_by_public_key(self.alice._address)
            assert self.baid >= 0, self.baid
            assert self.bob.friend_exists(self.baid)
            assert not self.bob.friend_exists(self.baid + 1)
            assert self.bob.self_get_friend_list_size() >= 1
            assert self.baid in self.bob.self_get_friend_list()
        except Exception as e:
            LOG.error(f"bob.friend_add EXCEPTION  {e}")
            return False
        finally:
            self.bob.callback_friend_message(None)

        return True

    def alice_add_bob_as_friend(self):
        """
        t:friend_add
        t:on_friend_request
        t:friend_by_public_key
        """
        MSG = 'Bob, this is Alice.'
        sSlot = 'friend_request'
        if not self.bAliceNeedAddBob(): return True

        def bobs_on_friend_request(iTox,
                                     public_key,
                                     message_data,
                                     message_data_size,
                                     *largs):
            LOG_DEBUG(f"bobs_on_friend_request: " +repr(message_data))
            try:
                assert str(message_data, 'UTF-8') == MSG
                LOG_INFO(f"bobs_on_friend_request: friend_added = True ")
            except Exception as e:
                LOG_WARN(f"bobs_on_friend_request: Exception {e}")
                # return
            setattr(self.alice, sSlot, True)

        setattr(self.alice, sSlot, None)
        inum = -1
        try:
            inum = self.alice.friend_add(self.bob._address, bytes(MSG, 'UTF-8'))
            assert inum >= 0, f"alice.friend_add !>= 0 {inum}"
            self.bob.callback_friend_request(bobs_on_friend_request)
            if not self.wait_otox_attrs(self.alice, [sSlot]):
                LOG_WARN(f"alice.friend_add NO wait {sSlot}")
                #? return False
            self.abid = self.alice.friend_by_public_key(self.bob._address)
            assert self.abid >= 0, self.abid
            assert self.alice.friend_exists(self.abid), "not exists"
            assert not self.alice.friend_exists(self.abid + 1), "exists +1"
            assert self.abid in self.alice.self_get_friend_list(), "not in list"
            assert self.alice.self_get_friend_list_size() >= 1, "list size"
        except Exception as e:
            LOG.error(f"alice.friend_add EXCEPTION {e}")
            return False
        finally:
            self.bob.callback_friend_message(None)
        return True

    def bob_add_alice_as_friend_and_status(self):
        if bUSE_NOREQUEST:
            assert self.bob_add_alice_as_friend_norequest()
        else:
            assert self.bob_add_alice_as_friend()

        #: Wait until both are online
        sSlot = 'friend_conn_status'
        setattr(self.bob, sSlot, False)
        def bobs_on_friend_connection_status(iTox, friend_id, iStatus, *largs):
            LOG_INFO(f"bobs_on_friend_connection_status {friend_id} ?>=0" +repr(iStatus))
            if iStatus > 0:
                self.bob.friend_conn_status = True

        self.bob.friend_status = None
        def bobs_on_friend_status(iTox, friend_id, iStatus, *largs):
            LOG_INFO(f"bobs_on_friend_status {friend_id} ?>=0" +repr(iStatus))
            if iStatus > 0:
                self.bob.friend_status = True

        self.alice.friend_conn_status = None
        def alices_on_friend_connection_status(iTox, friend_id, iStatus, *largs):
            LOG_INFO(f"alices_on_friend_connection_status {friend_id} ?>=0 " +repr(iStatus))
            if iStatus > 0:
                self.alice.friend_conn_status = True

        self.alice.friend_status = False
        def alices_on_friend_status(iTox, friend_id, iStatus, *largs):
            LOG_INFO(f"alices_on_friend_status {friend_id} ?>=0 " +repr(iStatus))
            if iStatus > 0:
                self.alice.friend_status = True

        self.alice.callback_friend_connection_status(alices_on_friend_connection_status)
        self.alice.callback_friend_status(alices_on_friend_status)
        try:
            LOG.info("bob_add_alice_as_friend_and_status waiting for alice connections")
            if not self.wait_otox_attrs(self.alice,
                                            ['friend_conn_status',
                                             'friend_status']):
                return False

            self.bob.callback_friend_connection_status(bobs_on_friend_connection_status)
            self.bob.callback_friend_status(bobs_on_friend_status)

            LOG.info("bob_add_alice_as_friend_and_status waiting for bob connections")
            if not self.wait_otox_attrs(self.bob,
                                            ['friend_conn_status',
                                             'friend_status']):
                LOG_WARN('bob_add_alice_as_friend_and_status NO')
                # return False
        except Exception as e:
            LOG.error(f"bob_add_alice_as_friend_and_status ERROR   {e}")
            return False
        finally:
            self.alice.callback_friend_connection_status(None)
            self.bob.callback_friend_connection_status(None)
            self.alice.callback_friend_status(None)
            self.bob.callback_friend_status(None)
        return True

    def bob_to_alice_connected(self):
        assert hasattr(self, 'baid')
        iRet = self.bob.friend_get_connection_status(self.baid)
        if iRet == TOX_CONNECTION['NONE']:
            LOG.warn("bob.friend_get_connection_status")
            return False
        return True

    def alice_to_bob_connected(self):
        assert hasattr(self, 'abid')
        iRet = self.alice.friend_get_connection_status(self.abid)
        if iRet == TOX_CONNECTION['NONE']:
            LOG.error("alice.friend_get_connection_status")
            return False
        return True

    def otox_test_groups_create(self,
                         otox,
                         group_name='test_group',
                         nick='test_nick',
                         topic='Test Topic', # str
                         ):
        privacy_state = enums.TOX_GROUP_PRIVACY_STATE['PUBLIC']

        iGrp = otox.group_new(privacy_state, group_name, nick)
        assert iGrp >= 0
        LOG.info(f"group iGrp={iGrp}")

        otox.group_set_topic(iGrp, topic)
        assert otox.group_get_topic(iGrp) == topic
        assert otox.group_get_topic_size(iGrp) == len(topic)

        name = otox.group_get_name(iGrp)
        if type(name) == bytes:
            name = str(name, 'utf-8')
        assert name == group_name, name
        assert otox.group_get_name_size(iGrp) == len(group_name)

        sPk = otox.group_self_get_public_key(iGrp)
        assert otox.group_get_password_size(iGrp) >= 0
        sP = otox.group_get_password(iGrp)
        assert otox.group_get_privacy_state(iGrp) == privacy_state

        assert  otox.group_get_number_groups() > 0
        LOG.info(f"group pK={sPk} iGrp={iGrp} n={otox.group_get_number_groups()}")
        return iGrp

    def otox_verify_group(self, otox, iGrp):
        """
        group_self_get_name
        group_self_get_peer_id
        group_self_get_public_key
        group_self_get_role
        group_self_get_status
        """

        group_number = iGrp
        assert type(iGrp) == int, "otox_test_groups_join iGrp not an int"
        assert iGrp < UINT32_MAX, "otox_test_groups_join iGrp failure UINT32_MAX"
        assert iGrp >= 0, f"otox_test_groups_join iGrp={iGrp} < 0"
        sGrp =  otox.group_get_chat_id(iGrp)
        assert len(sGrp) == enums.TOX_GROUP_CHAT_ID_SIZE * 2, \
          f"group sGrp={sGrp} {len(sGrp)} != {enums.TOX_GROUP_CHAT_ID_SIZE * 2}"
        sPk = otox.group_self_get_public_key(iGrp)
        LOG.info(f"otox_verify_group sPk={sPk} iGrp={iGrp} n={otox.group_get_number_groups()}")

        sName = otox.group_self_get_name(iGrp)
        iStat = otox.group_self_get_status(iGrp)
        iId = otox.group_self_get_peer_id(iGrp)
        iRole = otox.group_self_get_role(iGrp)
        iStat = otox.group_self_get_status(iGrp)
        LOG.info(f"otox_verify_group sName={sName} iStat={iStat} iId={iId} iRole={iRole} iStat={iStat}")

        try:
            bRet = otox.group_is_connected(iGrp)
        except Exception as e:
            LOG.warn(f"group_is_connected EXCEPTION {e}")
            return -1
        # chat->connection_state == CS_CONNECTED || chat->connection_state == CS_CONNECTING;
        if not bRet:
            LOG.warn(f"group_is_connected WARN not connected iGrp={iGrp}  n={otox.group_get_number_groups()}")
        else:
            LOG.info(f"group_is_connected SUCCESS connected iGrp={iGrp}  n={otox.group_get_number_groups()}")
            try:
                bRet = self.group_until_connected(otox, iGrp, iMax=2*THRESHOLD)
            except Exception as e:
                LOG.error(f"group_until_connected EXCEPTION {e}")
                return -1
        # chat->connection_state == CS_CONNECTED || chat->connection_state == CS_CONNECTING;
        if bRet:
            LOG.warn(f"group_until_connected WARN not connected iGrp={iGrp}  n={otox.group_get_number_groups()}")
        else:
            LOG.info(f"group_until_connected SUCCESS connected iGrp={iGrp}  n={otox.group_get_number_groups()}")

        message = bytes('hello', 'utf-8')
        bRet = otox.group_send_message(iGrp, TOX_MESSAGE_TYPE['NORMAL'], message)
        if not bRet:
            LOG.warn(f"group_send_message {bRet}")
        else:
            LOG.debug(f"group_send_message {bRet}")

    # 360497DA684BCE2A500C1AF9B3A5CE949BBB9F6FB1F91589806FB04CA039E313
    # 75D2163C19FEFFE51508046398202DDC321E6F9B6654E99BAE45FFEC134F05DE
    def otox_test_groups_join(self, otox,
                              chat_id="75d2163c19feffe51508046398202ddc321e6f9b6654e99bae45ffec134f05de",
                              nick='nick',
                              topic='Test Topic', # str
                              ):
        status = ''
        password = ''
        LOG.debug(f"group_join nick={nick} chat_id={chat_id}")
        try:
            iGrp = otox.group_join(chat_id, password, nick, status)
            LOG.info(f"otox_test_groups_join SUCCESS iGrp={iGrp} chat_id={chat_id}")
            self.otox_verify_group(otox, iGrp)

        except Exception as e:
            # gui
            LOG.error(f"otox_test_groups_join EXCEPTION {e}")
            raise

        return iGrp

    def otox_test_groups(self,
                         otox,
                         group_name='test_group',
                         nick='test_nick',
                         topic='Test Topic', # str
                         ):

        try:
            iGrp = self.otox_test_groups_create(otox, group_name, nick, topic)
            self.otox_verify_group(otox, iGrp)
        except Exception as e:
            LOG.error(f"otox_test_groups ERROR {e}")
            raise

        # unfinished
        # tox_group_peer_exit_cb
        # tox_callback_group_peer_join
        #     tox.callback_group_peer_status
        #     tox.callback_group_peer_name
        #     tox.callback_group_peer_exit
        #     tox.callback_group_peer_join
        return iGrp

    def wait_friend_get_connection_status(self, otox, fid, n=iN):
        i = 0
        while i < n:
            iRet = otox.friend_get_connection_status(fid)
            if iRet == TOX_CONNECTION['NONE']:
#                LOG.debug(f"wait_friend_get_connection_status NOT CONNECTED i={i} {iRet}")
                self.loop_until_connected()
            else:
                LOG.info("wait_friend_get_connection_status {iRet}")
                return True
            i += 1
        else:
            LOG.error(f"wait_friend_get_connection_status n={n}")
        return False

    def warn_if_no_cb(self, alice, sSlot):
        if not hasattr(alice, sSlot+'_cb') or \
          not getattr(alice, sSlot+'_cb'):
            LOG.warning(f"self.bob.{sSlot}_cb NOT EXIST")

    def warn_if_cb(self, alice, sSlot):
        if hasattr(self.bob, sSlot+'_cb') and \
          getattr(self.bob, sSlot+'_cb'):
            LOG.warning(f"self.bob.{sSlot}_cb EXIST")

    # tests are executed in order
    def test_notice_log(self): # works
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

    def test_tests_start(self): # works
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

    def test_bootstrap_local_netstat(self): # works
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

    def test_bootstrap_local(self): # works
        """
        t:call_bootstrap
        t:add_tcp_relay
        t:self_get_dht_id
        """
        # get port from /etc/tox-bootstrapd.conf 33445
        self.call_bootstrap()
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

    def test_bootstrap_iNmapInfo(self): # works
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
        ts.bootstrap_iNmapInfo(lElts, oTOX_OARGS, bIS_LOCAL, iNODES=8)

    def test_self_get_secret_key(self): # works
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

    def test_self_get_public_keys(self): # works
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

    def test_self_name(self): # works
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
    def test_sound_notification(self): # works
        """
        Plays sound notification
        :param  type of notification
        """
        from tests.toxygen_tests import test_sound_notification
        test_sound_notification(self)

    def test_address(self): # works
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

    def test_status_message(self): # works
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

    def test_self_get_udp_port(self): # works
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

    def test_self_get_tcp_port(self): # works
        """
        t:self_get_tcp_port
        """
        if hasattr(oTOX_OPTIONS, 'tcp_port') and oTOX_OPTIONS.tcp_port:
            # errors if tcp_port <= 0
            o = self.alice.self_get_tcp_port()
            LOG.info('self_get_tcp_port ' +repr(o))
            o = self.bob.self_get_tcp_port()
            LOG.info('self_get_tcp_port ' +repr(o))

    def test_get_dht_id(self): # works
        """
        t:self_get_dht_id
        """
        o1 = self.alice.self_get_dht_id()
        assert len(o1) == 64
        o2 = self.bob.self_get_dht_id()
        assert len(o2) == 64

    def test_bob_add_alice_as_friend_norequest(self): # works
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


    def test_alice_add_bob_as_friend_norequest(self): # works - intermittent failures
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

    def test_both_add_as_friend_norequest(self): # works
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

    def test_bob_add_alice_as_friend_and_status(self):
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
    def test_alice_add_bob_as_friend_and_status(self):
        assert self.alice_add_bob_as_friend_and_status()
        if hasattr(self, 'abid') and self.abid >= 0:
            self.alice.friend_delete(self.abid)

    def test_loop_until_connected(self): # works
        assert self.loop_until_connected()

    def test_bob_assert_connection_status(self): # works
        if self.bob.self_get_connection_status() == TOX_CONNECTION['NONE']:
            AssertionError("ERROR: NOT CONNECTED " \
                         +repr(self.bob.self_get_connection_status()))

    def test_alice_assert_connection_status(self): # works
        if self.alice.self_get_connection_status() == TOX_CONNECTION['NONE']:
            AssertionError("ERROR: NOT CONNECTED " \
                         +repr(self.alice.self_get_connection_status()))

    def test_bob_assert_mycon_status(self): # works
        if self.bob.mycon_status == False:
            AssertionError("ERROR: NOT CONNECTED " \
                         +repr(self.bob.mycon_status))

    def test_alice_assert_mycon_status(self): # works
        if self.alice.mycon_status == False:
            AssertionError("ERROR: NOT CONNECTED " \
                         +repr(self.alice.mycon_status))

    def test_bob_add_alice_as_friend(self): # works?
        try:
            if bUSE_NOREQUEST:
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

    def test_alice_add_bob_as_friend(self): # works!
        try:
            if bUSE_NOREQUEST:
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

    def test_both_add_as_friend(self): # works
        try:
            if bUSE_NOREQUEST:
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

    def test_groups_join(self):
        """
         t:group_join
         t:group_disconnect
         t:group_leave
         """
        if not self.get_connection_status():
            LOG.warning(f"test_groups_join NOT CONNECTED")
            self.loop_until_connected()

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

    def test_groups(self):
        """
         t:group_new
         t:group_disconnect
         t:group_get_name
         t:group_get_name_size
         t:group_get_topic
         t:group_get_topic_size
         t:group_get_privacy_state

         t:group_founder_set_password
         t:group_founder_set_peer_limit
         t:group_founder_set_privacy_state
         t:group_get_chat_id
         t:group_get_number_groups
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

#?    @unittest.skip("double free or corruption (fasttop)")
    @expectedFail('fails') # assertion fails on == MSG
    def test_on_friend_status_message(self): # fails
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

        def bob_on_friend_status_message(iTox, friend_id, new_status_message, new_status_size, *largs):
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
            if bUSE_NOREQUEST:
                assert self.bob_add_alice_as_friend_norequest()
#                assert self.alice_add_bob_as_friend_norequest()
            else:
                # no not connected error
                assert self.bob_add_alice_as_friend()
#                assert self.alice_add_bob_as_friend_norequest()

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

    def test_friend(self): # works! sometimes
        """
        t:friend_get_name
        t:friend_get_name_size
        t:on_friend_name
         """

        try:
            #: Test friend request
            if bUSE_NOREQUEST:
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
    def test_user_status(self): # fails
        """
        t:self_get_status
        t:self_set_status
        t:friend_get_status
        t:friend_get_status
        t:on_friend_status
        """
        sSlot = 'friend_status'

        setattr(self.bob, sSlot, None)
        def bobs_on_friend_set_status(iTox, friend_id, new_status, *largs):
            LOG_INFO(f"bobs_on_friend_set_status {friend_id} {new_status}")
            try:
                assert friend_id == self.baid
                assert new_status in [TOX_USER_STATUS['BUSY'], TOX_USER_STATUS['AWAY']]
            except Exception as e:
                LOG_WARN(f"bobs_on_friend_set_status EXCEPTION {e}")
            setattr(self.bob, sSlot, True)

        try:
            if bUSE_NOREQUEST:
                assert self.bob_add_alice_as_friend_norequest()
            else:
                assert self.bob_add_alice_as_friend()
            if not self.get_connection_status():
                LOG.warning(f"test_user_status NOT CONNECTED self.get_connection_status")
                self.loop_until_connected()

            self.bob.callback_friend_status(bobs_on_friend_set_status)
            self.warn_if_no_cb(self.bob, sSlot)
            sSTATUS = TOX_USER_STATUS['BUSY']
            self.alice.self_set_status(sSTATUS)
            sSlot = 'friend_status'
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
    def test_connection_status(self):
        """
        t:friend_get_connection_status
        t:on_friend_connection_status
        """
        sSlot = 'friend_connection_status'
        setattr(self.bob, sSlot, None)
        def bobs_on_friend_connection_status(iTox, friend_id, iStatus, *largs):
            LOG_INFO(f"bobs_on_friend_connection_status " +repr(iStatus))
            try:
                assert friend_id == self.baid
            except Exception as e:
                LOG_ERROR(f"bobs_on_friend_connection_status ERROR  {e}")
            setattr(self.bob, sSlot, True)

        opts = oToxygenToxOptions(oTOX_OARGS)
        setattr(self.bob, sSlot, True)
        try:
            if bUSE_NOREQUEST:
                assert self.bob_add_alice_as_friend_norequest()
            else:
                assert self.bob_add_alice_as_friend()

            self.bob.callback_friend_connection_status(bobs_on_friend_connection_status)

            LOG.info("test_connection_status killing alice")
            self.alice.kill() #! bang
            LOG.info("test_connection_status making alice")
            self.alice = Tox(opts, app=oAPP)
            LOG.info("test_connection_status maked alice")

            if not self.wait_otox_attrs(self.bob, [sSlot]):
                LOG_WARN(f' NO {sSlot}')
        except AssertionError as e:
            LOG.error(f"test_connection_status Failed test {e}")
            raise
        except Exception as e:
            LOG.error(f"bobs_on_friend_connection_status  {e}")
            raise
        finally:
            self.bob.callback_friend_connection_status(None)
            if hasattr(self, 'baid') and self.baid >= 0:
                self.bob.friend_delete(self.baid)

    @expectedFail('fails') # new name is empty
    def test_friend_name(self): # works!
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

        def bobs_on_friend_name(iTox, fid, newname, iNameSize, *largs):
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
            if bUSE_NOREQUEST:
                assert self.bob_add_alice_as_friend_norequest()
            else:
                assert self.bob_add_alice_as_friend()

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


    @expectedFail('fails')  # This client is currently not connected to the friend.
    def test_friend_message(self): # fails
        """
        t:on_friend_action
        t:on_friend_message
        t:friend_send_message
        """

       #: Test message
        MSG = 'Hi, Bob!'
        sSlot = 'friend_message'

        def alices_on_friend_message(iTox, fid, msg_type, message, iSize, *largs):
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
            if bUSE_NOREQUEST:
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
    def test_friend_action(self): # works! sometimes?
        """
        t:on_friend_action
        t:on_friend_message
        t:friend_send_message
        """

        #: Test action
        ACTION = 'Kick'
        sSlot = 'friend_read_action'
        setattr(self.bob, sSlot, None)
        def UNUSEDtheir_on_friend_action(iTox, fid, msg_type, action, *largs):
            LOG_DEBUG(f"their_on_friend_action {fid} {msg_type} {action}")
            try:
                assert msg_type == TOX_MESSAGE_TYPE['ACTION']
                assert action == ACTION
            except Exception as e:
                LOG_ERROR(f"their_on_friend_action EXCEPTION {e}")
            else:
                LOG_INFO(f"their_on_friend_action {action}")
            setattr(self.bob, 'friend_read_action', True)

        sSlot = 'friend_read_receipt'
        setattr(self.alice, sSlot, None)
        def their_on_read_reciept(iTox, fid, msg_id, *largs):
            LOG_DEBUG(f"their_on_read_reciept {fid} {msg_id}")
            sSlot = 'friend_read_receipt'
            try:
                # should be the receivers id
                assert fid == bob.baid or fid == alice.abid
                assert msg_id >= 0
            except Exception as e:
                LOG_ERROR(f"their_on_read_reciept {e}")
            else:
                LOG_INFO(f"their_on_read_reciept {fid}")
            setattr(self.alice, 'friend_read_receipt', True)

        try:
            if bUSE_NOREQUEST:
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

    def test_alice_typing_status(self): # works
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
        def bob_on_friend_typing(iTox, fid, is_typing, *largs):
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
            if bUSE_NOREQUEST:
                assert self.both_add_as_friend_norequest()
            else:
                assert self.both_add_as_friend()

            if not self.get_connection_status():
                LOG.warning(f"test_friend_typing NOT CONNECTED")
                self.loop_until_connected()

            self.bob.callback_friend_typing(bob_on_friend_typing)
            self.warn_if_no_cb(self.bob, sSlot)
            self.alice.self_set_typing(self.abid, False)
            if not self.wait_otox_attrs(self.bob, [sSlot]):
                LOG_WARN(f"bobs_on_friend_typing NO {sSlot}")
            if not hasattr(self.bob, sSlot+'_cb') or \
               not getattr(self.bob, sSlot+'_cb'):
                LOG.warning(f"self.bob.{sSlot}_cb NOT EXIST")
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

    @unittest.skip('unfinished')
    def test_file_transfer(self): # unfinished
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

        if bUSE_NOREQUEST:
            assert self.both_add_as_friend_norequest()
        else:
            assert self.both_add_as_friend()

        FRIEND_NUMBER = self.baid
        FILE_NUMBER = 1
        FILE = os.urandom(1024 * 1024)
        FILE_NAME = b"/tmp/test.bin"
        if not os.path.exists(FILE_NAME):
            with open(FILE_NAME, 'wb') as oFd:
                oFd.write(FILE)
        FILE_SIZE = len(FILE)
        OFFSET = 567

        m = hashlib.md5()
        m.update(FILE[OFFSET:])
        FILE_DIGEST = m.hexdigest()

        CONTEXT = { 'FILE': bytes(), 'RECEIVED': 0, 'START': False, 'SENT': 0 }

        def alice_on_file_recv(iTox, fid, file_number, kind, size, filename):
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

        def alice_on_file_recv_control(iTox, fid, file_number, control, *largs):
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
        def alice_on_file_recv_chunk(iTox, fid, file_number, position, iNumBytes, *largs):
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
                    return

                CONTEXT['FILE'] += data
                CONTEXT['RECEIVED'] += len(data)
                # if CONTEXT['RECEIVED'] < FILE_SIZE:
                #    assert self.file_data_remaining(
                #        fid, file_number, 1) == FILE_SIZE - CONTEXT['RECEIVED']
            except Exception as e:
                LOG_ERROR(f"ALICE_ON_file_recv_chunk {e}")

        # AliceTox.on_file_send_request = on_file_send_request
        # AliceTox.on_file_control = on_file_control
        # AliceTox.on_file_data = on_file_data

        try:
            self.alice.callback_file_recv(alice_on_file_recv)
            self.alice.callback_file_recv_control(alice_on_file_recv_control)
            self.alice.callback_file_recv_chunk(alice_on_file_recv_chunk)

            self.bob.completed = False
            def bob_on_file_recv_control2(iTox, fid, file_number, control):
                LOG_DEBUG(f"BOB_ON_file_recv_control2 {fid} {file_number} control={control}")
                if control == TOX_FILE_CONTROL['RESUME']:
                    CONTEXT['START'] = True
                elif control == TOX_FILE_CONTROL['CANCEL']:
                    self.bob.completed = True
                    pass

            def bob_on_file_chunk_request(iTox, fid, file_number, position, length, *largs):
                LOG_DEBUG(f"BOB_ON_file_chunk_request {fid} {file_number}")
                if length == 0:
                    return
                data = FILE[position:(position + length)]
                self.bob.file_send_chunk(fid, file_number, position, data)

            sSlot = 'file_recv_control'
            self.bob.callback_file_recv_control(bob_on_file_recv_control2)
            self.bob.callback_file_chunk_request(bob_on_file_chunk_request)

            # was FILE_ID = FILE_NAME
            FILE_ID = 32*'1' #

            # required
            assert self.wait_friend_get_connection_status(self.bob, self.baid, n=iN)
            assert self.wait_friend_get_connection_status(self.alice, self.abid, n=iN)

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
                raise AssertionError(f"test_file_transfer bob.file_send {THRESHOLD // 2}")

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
    def test_tox_savedata(self): # works sorta
        """
        t:get_savedata_size
        t:get_savedata
        """
        # Fatal Python error: Aborted
        # "/var/local/src/toxygen_wrapper/wrapper/tox.py", line 180 in kill
        return

        assert self.alice.get_savedata_size() > 0
        data = self.alice.get_savedata()
        assert data is not None
        addr = self.alice.self_get_address()
        # self._address

        try:
            LOG.info("test_tox_savedata alice.kill")
            # crashes
            self.alice.kill()
        except:
            pass

        oArgs = oTOX_OARGS
        opts = oToxygenToxOptions(oArgs)
        opts.savedata_data = data
        opts.savedata_length = len(data)

        self.alice = Tox(tox_options=opts)
        if addr != self.alice.self_get_address():
            LOG.warning("test_tox_savedata " +
                      f"{addr} != {self.alice.self_get_address()}")
        else:
            LOG.info("passed test_tox_savedata")

    def test_kill(self): #
        import threading
        LOG.info(f"THE END {threading.active_count()}")
        self.tearDown()
        LOG.info(f"THE END {threading.enumerate()}")


def vOargsToxPreamble(oArgs, Tox, ToxTest):

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

def iMain(oArgs):
    failfast=True

    vOargsToxPreamble(oArgs, Tox, ToxSuite)
    # https://stackoverflow.com/questions/35930811/how-to-sort-unittest-testcases-properly/35930812#35930812
    cases = ts.suiteFactory(*ts.caseFactory([ToxSuite]))
    if color_runner:
        runner = color_runner.runner.TextTestRunner(verbosity=2, failfast=failfast)
    else:
        runner = unittest.TextTestRunner(verbosity=2, failfast=failfast, warnings='ignore')
    runner.run(cases)

def oToxygenToxOptions(oArgs):
    data = None
    tox_options = wrapper.tox.Tox.options_new()
    if oArgs.proxy_type:
        tox_options.contents.proxy_type = int(oArgs.proxy_type)
        tox_options.contents.proxy_host = bytes(oArgs.proxy_host, 'UTF-8')
        tox_options.contents.proxy_port = int(oArgs.proxy_port)
        tox_options.contents.udp_enabled = False
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

    #? tox_options.contents.log_callback = LOG
    if tox_options._options_pointer:
        # LOG.debug("Adding logging to tox_options._options_pointer ")
        ts.vAddLoggerCallback(tox_options, ts.on_log)
    else:
        LOG.warning("No tox_options._options_pointer " +repr(tox_options._options_pointer))

    return tox_options

def oArgparse(lArgv):
    parser = ts.oMainArgparser()
    parser.add_argument('--norequest',type=str, default='False',
                        choices=['True','False'],
                        help='Use _norequest')
    parser.add_argument('profile', type=str, nargs='?', default=None,
                        help='Path to Tox profile')
    oArgs = parser.parse_args(lArgv)

    for key in ts.lBOOLEANS:
        if key not in oArgs: continue
        val = getattr(oArgs, key)
        setattr(oArgs, key, bool(val))

    if hasattr(oArgs, 'sleep'):
        if oArgs.sleep == 'qt':
            pass # broken or gevent.sleep(idle_period)
        elif oArgs.sleep == 'gevent':
            pass # broken or gevent.sleep(idle_period)
        else:
            oArgs.sleep = 'time'

    return oArgs

def main(lArgs=None):
    global     oTOX_OARGS
    if lArgs is None: lArgs = []
    oArgs = oArgparse(lArgs)
    global bIS_LOCAL
    bIS_LOCAL = oArgs.network in ['newlocal', 'localnew', 'local']
    oTOX_OARGS = oArgs
    setattr(oTOX_OARGS, 'bIS_LOCAL', bIS_LOCAL)
    bIS_LOCAL = True
    setattr(oTOX_OARGS, 'bIS_LOCAL', bIS_LOCAL)
    # oTOX_OPTIONS = ToxOptions()
    global oTOX_OPTIONS
    oTOX_OPTIONS = oToxygenToxOptions(oArgs)
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
    sys.exit(main(sys.argv[1:]))
