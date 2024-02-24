# -*- mode: python; indent-tabs-mode: nil; py-indent-offset: 4; coding: utf-8 -*-

import logging
import os
import random
import re
import sys
import time
import threading
from ctypes import *
from typing import Union, Callable, Optional

import toxygen_wrapper.toxcore_enums_and_consts as enums
from toxygen_wrapper.tox import Tox, UINT32_MAX, ToxError

from toxygen_wrapper.toxcore_enums_and_consts import (TOX_ADDRESS_SIZE, TOX_CONNECTION,
                                              TOX_FILE_CONTROL,
                                              TOX_MESSAGE_TYPE,
                                              TOX_SECRET_KEY_SIZE,
                                              TOX_USER_STATUS)

try:
    import support_testing as ts
except ImportError:
    import toxygen_wrapper.tests.support_testing as ts
sleep = time.sleep

ADDR_SIZE = 38 * 2
CLIENT_ID_SIZE = 32 * 2
THRESHOLD = 120 # >25
fSOCKET_TIMEOUT = 15.0
iLOOP_N = 50

iN = 6

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

class WrapperMixin():

    def bBobNeedAlice(self) -> bool:
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

    def bAliceNeedAddBob (self) -> bool:
        if hasattr(self, 'abid') and self.abid >= 0 and \
          self.abid in self.alice.self_get_friend_list():
            LOG.warn(f"setUp BOB IS ALREADY IN ALICES FRIEND LIST")
            return False
        if self.alice.self_get_friend_list_size() >= 1:
            LOG.warn(f"setUp ALICE STILL HAS A FRIEND LIST")
            return False
        return True

    def get_connection_status(self) -> bool:
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

    def loop(self, n) -> None:
        """
        t:iterate
        t:iteration_interval
        """
        interval = self.bob.iteration_interval()
        for i in range(n):
            self.alice.iterate()
            self.bob.iterate()
            sleep(interval / 1000.0)

    def call_bootstrap(self, num: Optional[int] = None, lToxes:Union[list[int], None] =None, i:int =0, fsocket_timeout:float = fSOCKET_TIMEOUT) -> None:
        if num == None: num=ts.iNODES
        if lToxes is None:
            lToxes = [self.alice, self.bob]
#        LOG.debug(f"call_bootstrap network={oTOX_OARGS.network}")
        otox = lToxes[0]
        if otox._args.network in ['new', 'newlocal', 'localnew']:
            ts.bootstrap_local(self.lUdp, lToxes)
        elif not ts.bAreWeConnected():
            LOG.warning('we are NOT CONNECTED')
        else:
            random.shuffle(self.lUdp)
            if otox._args.proxy_port > 0:
                lElts = self.lUdp[:1]
            else:
                lElts = self.lUdp[:num+i]
            LOG.debug(f"call_bootstrap ts.bootstrap_udp {len(lElts)}")
            ts.bootstrap_udp(lElts, lToxes, fsocket_timeout=fsocket_timeout)
            random.shuffle(self.lTcp)
            lElts = self.lTcp[:num+i]
            LOG.debug(f"call_bootstrap ts.bootstrap_tcp {len(lElts)}")
            ts.bootstrap_tcp(lElts, lToxes, fsocket_timeout=fsocket_timeout)

    def group_until_connected(self, otox, group_number:int, num: Optional[int] = None, iMax:int = THRESHOLD, fsocket_timeout:float = fSOCKET_TIMEOUT) -> bool:
        """
        """
        i = 0
        bRet = None
        while i <= iMax :
            i += 1
            iRet = otox.group_is_connected(group_number)
            if iRet == True:
                bRet = True
                break
            if i % 5 == 0:
                j = i//5 + 1
                self.call_bootstrap(num, lToxes=None, i=j, fsocket_timeout=fsocket_timeout)
                s = ''
                if i == 0: s = '\n'
                LOG.info(s+f"group_until_connected #{i} iRet={iRet}" \
                         +f" BOBS={otox.self_conn_status}" \
                         +f" last={int(otox.mycon_time)}" )
            self.loop(iLOOP_N)
        else:
            bRet = False

        if bRet:
            LOG.info(f"group_until_connected True i={i} iMax={iMax}" \
                     +f" BOB={otox.self_get_connection_status()}" \
                     +f" last={int(otox.mycon_time)}" )
            return True
        else:
            LOG.warning(f"group_until_connected False i={i}" \
                        +f" iMax={iMax}" \
                        +f" BOB={otox.self_get_connection_status()}" \
                        +f" last={int(otox.mycon_time)}" )
            return False

    def loop_until_connected(self, otox=None, num: Optional[int] = None, fsocket_timeout:float = fSOCKET_TIMEOUT) -> bool:
        """
        t:on_self_connection_status
        t:self_get_connection_status
        """
        i = 0
        num = 4
        bRet = None
        if otox is None: otox = self.bob
        while i <= otox._args.test_timeout :
            i += 1
            if (self.alice.self_conn_status and self.bob.self_conn_status):
                bRet = True
                break
            if i % 5 == 0:
                j = i//5 + 1
                self.call_bootstrap(num, lToxes=None, i=j, fsocket_timeout=fsocket_timeout)
                s = ''
                if i == 0: s = '\n'
                LOG.info(s+"loop_until_connected " \
                         +" #" + str(i) \
                         +" BOB=" +repr(self.bob.self_get_connection_status()) \
                         +" ALICE=" +repr(self.alice.self_get_connection_status())
                         +f" BOBS={self.bob.self_conn_status}" \
                         +f" ALICES={self.alice.self_conn_status}" \
                         +f" last={int(self.bob.mycon_time)}" )
            if (self.alice.self_conn_status and self.bob.self_conn_status):
                bRet = True
                break
            if (self.alice.self_get_connection_status() and
                self.bob.self_get_connection_status()):
                LOG_WARN(f"loop_until_connected disagree status() DISAGREE" \
                         +f' self.bob.self_conn_status={self.bob.self_conn_status}' \
                         +f' alice.self_conn_status={self.alice.self_conn_status}' \
                         +f" last={int(self.bob.mycon_time)}" )
                bRet = True
                break
            self.loop(iLOOP_N)
        else:
            bRet = False

        if bRet or \
            ( self.bob.self_get_connection_status() != TOX_CONNECTION['NONE'] and \
              self.alice.self_get_connection_status() != TOX_CONNECTION['NONE'] ):
            LOG.info(f"loop_until_connected returning True i={i}" \
                     +f" BOB={self.bob.self_get_connection_status()}" \
                     +f" ALICE={self.alice.self_get_connection_status()}" \
                     +f" last={int(self.bob.mycon_time)}" )
            return True

        otox._args.test_timeout += 5
        LOG.warning(f"loop_until_connected returning False i={i}" \
                 +f" BOB={self.bob.self_get_connection_status()}" \
                 +f" ALICE={self.alice.self_get_connection_status()}" \
                 +f" last={int(self.bob.mycon_time)}" )
        return False

    def wait_objs_attr(self, objs: list, attr: str, fsocket_timeout:float = fSOCKET_TIMEOUT) -> bool:
        i = 0
        otox = objs[0]
        while i <= otox._args.test_timeout:
            i += 1
            if i % 5 == 0:
                num = None
                j = 0
                j = i//5
                self.call_bootstrap(num, lToxes=objs, i=j, fsocket_timeout=fsocket_timeout)
                LOG.debug(f"wait_objs_attr {objs} for {attr} {i}")
            if all([getattr(obj, attr) for obj in objs]):
                return True
            self.loop(iLOOP_N)
        else:
            otox._args.test_timeout += 1
            LOG.warn(f"wait_objs_attr for {attr} i >= {otox._args.test_timeout}")

        return all([getattr(obj, attr) is not None for obj in objs])

    def wait_otox_attrs(self, obj, attrs: list[str], fsocket_timeout:float = fSOCKET_TIMEOUT) -> bool:
        assert all(attrs), f"wait_otox_attrs {attrs}"
        i = 0
        otox = obj
        while i <= otox._args.test_timeout:
            i += 1
            if i % 5 == 0:
                num = None
                j = 0
                if obj.mycon_time == 1:
                    # start with 4 random nodes ti bootstrap
                    num = 4
                    # every 10 sec add another random nodes to bootstrap
                    j = i//10 + 1
                if obj.self_get_connection_status() == TOX_CONNECTION['NONE']:
                    self.call_bootstrap(num, lToxes=[obj], i=j, fsocket_timeout=fsocket_timeout)
                LOG.debug(f"wait_otox_attrs {obj.name} for {attrs} {i}" \
                         +f" last={int(obj.mycon_time)}")
            if all([getattr(obj, attr) is not None for attr in attrs]):
                return True
            self.loop(iLOOP_N)
        else:
            LOG.warning(f"wait_otox_attrs i >= {otox._args.test_timeout} attrs={attrs} results={[getattr(obj, attr) for attr in attrs]}")

        return all([getattr(obj, attr) for attr in attrs])

    def wait_ensure_exec(self, method, args:list, fsocket_timeout:float = fSOCKET_TIMEOUT) -> bool:
        i = 0
        oRet = None
        while i <= self.bob._args.test_timeout:
            i += 1
            if i % 5 == 0:
                # every 10 sec add another random nodes to bootstrap
                j = i//10 + 1
                self.call_bootstrap(num=None, lToxes=None, i=j, fsocket_timeout=fsocket_timeout)
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
        else:
            LOG.error(f"wait_ensure_exec i >=  {1*self.bob._args.test_timeout}")
            return False

        return oRet

    def bob_add_alice_as_friend_norequest(self) -> bool:
        if not self.bBobNeedAlice(): return True

        apk = self.alice.self_get_public_key()
        iRet = self.bob.friend_add_norequest(apk)
        if iRet < 0:
            return False
        self.baid = self.bob.friend_by_public_key(apk)
        assert self.baid >= 0, self.baid
        assert self.bob.friend_exists(self.baid), "bob.friend_exists"
        assert not self.bob.friend_exists(self.baid + 1)
        assert self.baid in self.bob.self_get_friend_list()
        assert self.bob.self_get_friend_list_size() >= 1
        return True

    def alice_add_bob_as_friend_norequest(self) -> bool:
        if not self.bAliceNeedAddBob(): return True

        bpk = self.bob.self_get_public_key()
        iRet = self.alice.friend_add_norequest(bpk)
        if iRet < 0:
            return False
        self.abid = self.alice.friend_by_public_key(bpk)
        assert self.abid >= 0, self.abid
        assert self.abid in self.alice.self_get_friend_list()
        assert self.alice.friend_exists(self.abid), "alice.friend_exists"
        assert not self.alice.friend_exists(self.abid + 1)
        assert self.alice.self_get_friend_list_size() >= 1
        return True

    def both_add_as_friend(self) -> bool:
        if self.bob._args.norequest:
            assert self.bob_add_alice_as_friend_norequest()
            assert self.alice_add_bob_as_friend_norequest()
        else:
            assert self.bob_add_alice_as_friend()
            assert self.alice_add_bob_as_friend()
        if not hasattr(self, 'baid') or self.baid < 0:
            LOG.warn("both_add_as_friend no bob, baid")
        if not hasattr(self, 'abid') or self.abid < 0:
            LOG.warn("both_add_as_friend no alice, abid")
        return True

    def both_add_as_friend_norequest(self) -> bool:
        if self.bBobNeedAlice():
            assert self.bob_add_alice_as_friend_norequest()
        if self.bAliceNeedAddBob():
            assert self.alice_add_bob_as_friend_norequest()
        if not hasattr(self.bob, 'baid') or self.bob.baid < 0:
            LOG.warn("both_add_as_friend_norequest no bob, baid")
        if not hasattr(self.alice, 'abid') or self.alice.abid < 0:
            LOG.warn("both_add_as_friend_norequest no alice, abid")

        #: Test last online
#?        assert self.alice.friend_get_last_online(self.abid) is not None
#?        assert self.bob.friend_get_last_online(self.baid) is not None
        return True

    def bob_add_alice_as_friend(self) -> bool:
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
                                     *largs) -> None:
            try:
                assert str(message_data, 'UTF-8') == MSG
                LOG_INFO(f"alices_on_friend_request: {sSlot} = True ")
            except Exception as e:
                LOG_WARN(f"alices_on_friend_request: EXCEPTION  {e}")
                # return
            setattr(self.bob, sSlot, True)

        setattr(self.bob, sSlot, None)
        apk = self.alice.self_get_public_key()
        inum = -1
        try:
            inum = self.bob.friend_add(self.alice._address, bytes(MSG, 'UTF-8'))
            assert inum >= 0, f"bob_add_alice_as_friend !>= 0 {inum}"
            # need a friend connected?
            if not self.get_connection_status():
                LOG.warning(f"test_groups_join NOT CONNECTED")
                self.loop_until_connected(self.bob)
            self.alice.callback_friend_request(alices_on_friend_request)
            if not self.wait_otox_attrs(self.bob, [sSlot]):
                LOG_WARN(f"bob_add_alice_as_friend NO setting {sSlot}")
                return False
            self.baid = self.bob.friend_by_public_key(apk)
            assert self.baid >= 0, self.baid
            assert self.bob.friend_exists(self.baid)
            assert not self.bob.friend_exists(self.baid + 1)
            assert self.bob.self_get_friend_list_size() >= 1
            assert self.baid in self.bob.self_get_friend_list()
        except Exception as e:
            LOG.error(f"bob_add_alice_as_friend EXCEPTION  {e}")
            return False
        finally:
            self.bob.callback_friend_message(None)

        return True

    def alice_add_bob_as_friend(self) -> bool:
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
                                     *largs) -> None:
            LOG_DEBUG(f"bobs_on_friend_request: " +repr(message_data))
            try:
                assert str(message_data, 'UTF-8') == MSG
            except Exception as e:
                LOG_WARN(f"bobs_on_friend_request: Exception {e}")
                # return
            setattr(self.alice, sSlot, True)

        LOG_INFO(f"bobs_on_friend_request: {sSlot} = True ")
        setattr(self.alice, sSlot, None)
        bpk = self.bob.self_get_public_key()
        inum = -1
        try:
            inum = self.alice.friend_add(self.bob._address, bytes(MSG, 'UTF-8'))
            assert inum >= 0, f"alice.friend_add !>= 0 {inum}"
            self.bob.callback_friend_request(bobs_on_friend_request)
            if not self.wait_otox_attrs(self.alice, [sSlot]):
                LOG_WARN(f"alice.friend_add NO wait {sSlot}")
                return False
            self.abid = self.alice.friend_by_public_key(bpk)
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

    def bob_add_alice_as_friend_and_status(self) -> bool:
        if self.bob._args.norequest:
            assert self.bob_add_alice_as_friend_norequest()
        else:
            assert self.bob_add_alice_as_friend()

        #: Wait until both are online
        sSlot = 'friend_status'
        setattr(self.bob, sSlot, None)
        def bobs_on_friend_status(iTox, friend_id, iStatus, *largs) -> None:
            LOG_INFO(f"bobs_on_friend_status {friend_id} ?>=0 iS={iStatus}")
            setattr(self.bob, sSlot, False)


        sSlot = 'friend_status'
        setattr(self.alice, sSlot, None)
        def alices_on_friend_status(iTox, friend_id, iStatus, *largs) -> None:
            LOG_INFO(f"alices_on_friend_status {friend_id} ?>=0 iS={iStatus}")
            setattr(self.alice, sSlot, False)

        try:
            # need a friend connected?
            if not self.get_connection_status():
                self.loop_until_connected(self.bob)
            LOG.info("bob_add_alice_as_friend_and_status waiting for alice connections")
            if not self.wait_otox_attrs(self.alice,
                                            [ # 'friend_conn_status',
                                             'friend_status']):
                return False

#            self.bob.callback_friend_connection_status(bobs_on_friend_connection_status)
            self.bob.callback_friend_status(bobs_on_friend_status)
#            self.alice.callback_friend_connection_status(alices_on_friend_connection_status)
            self.alice.callback_friend_status(alices_on_friend_status)

            LOG.info("bob_add_alice_as_friend_and_status waiting for bob connections")
            if not self.wait_otox_attrs(self.bob,
                                            [ # 'friend_conn_status',
                                             'friend_status']):
                LOG_WARN('bob_add_alice_as_friend_and_status NO')
                # return False
        except Exception as e:
            LOG.error(f"bob_add_alice_as_friend_and_status ERROR   {e}")
            return False
        finally:
#            self.alice.callback_friend_connection_status(None)
#            self.bob.callback_friend_connection_status(None)
            self.alice.callback_friend_status(None)
            self.bob.callback_friend_status(None)
        return True

    def otox_test_groups_create(self,
                         otox,
                         group_name='test_group',
                         nick='test_nick',
                         topic='Test Topic', # str
                         ) -> int:
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

        assert  otox.group_get_number_groups() > 0, "numg={otox.group_get_number_groups()}"
        LOG.info(f"group pK={sPk} iGrp={iGrp} numg={otox.group_get_number_groups()}")
        return iGrp

    def otox_verify_group(self, otox, iGrp) -> None:
        """
        group_self_get_name
        group_self_get_peer_id
        group_self_get_public_key
        group_self_get_role
        group_self_get_status
        group_self_set_name
        """

        group_number = iGrp
        try:
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

            assert otox.group_self_set_name(iGrp, "NewName")

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
                bRet = self.group_until_connected(otox, iGrp, iMax=2*otox._args.test_timeout)
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
                         ) -> int:

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

    def wait_friend_get_connection_status(self, otox, fid:int, n:int = iN) -> int:
        i = 0
        while i < n:
            i += 1
            iRet = otox.friend_get_connection_status(fid)
            if iRet == TOX_CONNECTION['NONE']:
                LOG.debug(f"wait_friend_get_connection_status NOT CONNECTED i={i}  fid={fid} {iRet}")
                self.loop_until_connected(otox)
            else:
                LOG.info(f"wait_friend_get_connection_status fid={fid} {iRet}")
                return True
        else:
            LOG.error(f"wait_friend_get_connection_status fid={fid} n={n}")
        return False

    def warn_if_no_cb(self, alice, sSlot:str) -> None:
        if not hasattr(alice, sSlot+'_cb') or \
          not getattr(alice, sSlot+'_cb'):
            LOG.warning(f"self.bob.{sSlot}_cb NOT EXIST")

    def warn_if_cb(self, alice, sSlot:str) -> None:
        if hasattr(self.bob, sSlot+'_cb') and \
          getattr(self.bob, sSlot+'_cb'):
            LOG.warning(f"self.bob.{sSlot}_cb EXIST")
