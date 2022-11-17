# -*- mode: python; indent-tabs-mode: nil; py-indent-offset: 4; coding: utf-8 -*-

import getpass
import os
import re
import select
import shutil
import socket
import sys
import time

if False:
    import cepa as stem
    from cepa.connection import MissingPassword
    from cepa.control import Controller
    from cepa.util.tor_tools import is_valid_fingerprint
else:
    import stem
    from stem.connection import MissingPassword
    from stem.control import Controller
    from stem.util.tor_tools import is_valid_fingerprint

global LOG
import logging
import warnings

warnings.filterwarnings('ignore')
LOG = logging.getLogger()

bHAVE_TORR = shutil.which('tor-resolve')

# we check these each time but we got them by sorting bad relays
# in the wild we'll keep a copy here so we can avoid restesting
yKNOWN_NODNS = """
---
  - 0x0.is
  - a9.wtf
  - aklad5.com
  - artikel5ev.de
  - arvanode.net
  - dodo.pm
  - dra-family.github.io
  - eraldonion.org
  - erjan.net
  - galtland.network
  - ineapple.cx
  - lonet.sh
  - moneneis.de
  - olonet.sh
  - or-exit-2.aa78i2efsewr0neeknk.xyz
  - or.wowplanet.de
  - ormycloud.org
  - plied-privacy.net
  - rivacysvcs.net
  - redacted.org
  - rification-for-nusenu.net
  - rofl.cat
  - rsv.ch
  - sv.ch
  - thingtohide.nl
  - tikel10.org
  - tor.wowplanet.de
  - tor-exit-2.aa78i2efsewr0neeknk.xyz
  - tor-exit-3.aa78i2efsewr0neeknk.xyz
  - torix-relays.org
  - tse.com
  - tuxli.org
  - w.digidow.eu
  - w.cccs.de
"""

def oMakeController(sSock='', port=9051):
    import getpass
    if sSock and os.path.exists(sSock):
        controller = Controller.from_socket_file(path=sSock)
    else:
        controller = Controller.from_port(port=port)
    sys.stdout.flush()
    p = getpass.unix_getpass(prompt='Controller Password: ', stream=sys.stderr)
    controller.authenticate(p)
    return controller

oSTEM_CONTROLER = None
def oGetStemController(log_level=10, sock_or_pair='/run/tor/control'):

    global oSTEM_CONTROLER
    if oSTEM_CONTROLER: return oSTEM_CONTROLER
    import stem.util.log
    stem.util.log.Runlevel = log_level

    if os.path.exists(sock_or_pair):
        LOG.info(f"controller from socket {sock_or_pair}")
        controller = Controller.from_socket_file(path=sock_or_pair)
    else:
        if ':' in sock_or_pair:
            port = sock_or_pair.split(':')[1]
        else:
            port = sock_or_pair
        try:
           port = int(port)
        except: port = 9051
        LOG.info(f"controller from port {port}")
        controller = Controller.from_port(port=port)
    try:
        controller.authenticate()
    except (Exception, MissingPassword):
        sys.stdout.flush()
        p = getpass.unix_getpass(prompt='Controller Password: ', stream=sys.stderr)
        controller.authenticate(p)
    oSTEM_CONTROLER = controller
    LOG.debug(f"{controller}")
    return oSTEM_CONTROLER

def bAreWeConnected():
    # FixMe: Linux only
    sFile = f"/proc/{os.getpid()}/net/route"
    if not os.path.isfile(sFile): return None
    i = 0
    for elt in open(sFile, "r").readlines():
        if elt.startswith('Iface'): continue
        if elt.startswith('lo'): continue
        i += 1
    return i > 0

def sMapaddressResolv(target, iPort=9051, log_level=10):
    if not stem:
        LOG.warn('please install the stem Python package')
        return ''

    try:
        controller = oGetStemController(log_level=log_level)

        map_dict = {"0.0.0.0": target}
        map_ret = controller.map_address(map_dict)

        return map_ret
    except Exception as e:
        LOG.exception(e)
    return ''

def vwait_for_controller(controller, wait_boot=10):
    if bAreWeConnected() is False:
        raise SystemExit("we are not connected")
    percent = i = 0
    # You can call this while boostrapping
    while percent < 100 and i < wait_boot:
        bootstrap_status = controller.get_info("status/bootstrap-phase")
        progress_percent = re.match('.* PROGRESS=([0-9]+).*', bootstrap_status)
        percent = int(progress_percent.group(1))
        LOG.info(f"Bootstrapping {percent}%")
        time.sleep(5)
        i += 5

def bin_to_hex(raw_id, length=None):
    if length is None: length = len(raw_id)
    res = ''.join('{:02x}'.format(raw_id[i]) for i in range(length))
    return res.upper()

def lIntroductionPoints(controller=None, lOnions=[], itimeout=120, log_level=10):
    """now working !!! stem 1.8.x timeout must be huge >120
    'Provides the descriptor for a hidden service. The **address** is the
    '.onion' address of the hidden service '
    What about Services?
    """
    try:
        from cryptography.utils import int_from_bytes
    except ImportError:
        import cryptography.utils

        # guessing - not in the current cryptography but stem expects it
        def int_from_bytes(**args): return int.to_bytes(*args)
        cryptography.utils.int_from_bytes = int_from_bytes
    # this will fai if the trick above didnt work
    from stem.prereq import is_crypto_available
    is_crypto_available(ed25519=True)

    from queue import Empty

    from stem import Timeout
    from stem.client.datatype import LinkByFingerprint
    from stem.descriptor.hidden_service import HiddenServiceDescriptorV3

    if type(lOnions) not in [set, tuple, list]:
        lOnions = list(lOnions)
    if controller is None:
        controller = oGetStemController(log_level=log_level)
    l = []
    for elt in lOnions:
        LOG.info(f"controller.get_hidden_service_descriptor {elt}")
        try:
            desc = controller.get_hidden_service_descriptor(elt,
                                                            await_result=True,
                                                            timeout=itimeout)
    #        LOG.log(40, f"{dir(desc)} get_hidden_service_descriptor")
            # timeouts 20 sec
            # mistakenly a HSv2 descriptor
            hs_address = HiddenServiceDescriptorV3.from_str(str(desc))  # reparse as HSv3
            oInnerLayer = hs_address.decrypt(elt)
    #        LOG.log(40, f"{dir(oInnerLayer)}")

            # IntroductionPointV3
            n = oInnerLayer.introduction_points
            if not n:
                LOG.warn(f"NO introduction points for {elt}")
                continue
            LOG.info(f"{elt} {len(n)} introduction points")
            lp = []
            for introduction_point in n:
                for linkspecifier in introduction_point.link_specifiers:
                    if isinstance(linkspecifier, LinkByFingerprint):
                        # LOG.log(40, f"Getting fingerprint for {linkspecifier}")
                        if hasattr(linkspecifier, 'fingerprint'):
                            assert len(linkspecifier.value) == 20
                            lp += [bin_to_hex(linkspecifier.value)]
            LOG.info(f"{len(lp)} introduction points for {elt}")
            l += lp
        except (Empty, Timeout,) as e: # noqa
            LOG.warn(f"Timed out getting introduction points for {elt}")
            continue
        except Exception as e:
          LOG.exception(e)
    return l

def zResolveDomain(domain):
    try:
        ip = sTorResolve(domain)
    except Exception as e: # noqa
        ip = ''
    if ip == '':
        try:
            lpair = getaddrinfo(domain, 443)
        except Exception as e:
            LOG.warn(f"{e}")
            lpair = None
        if lpair is None:
            LOG.warn(f"TorResolv and getaddrinfo failed for {domain}")
            return ''
        ip = lpair[0]
    return ip

def sTorResolve(target,
                verbose=False,
                sHost='127.0.0.1',
                iPort=9050,
                SOCK_TIMEOUT_SECONDS=10.0,
                SOCK_TIMEOUT_TRIES=3,
                ):
    MAX_INFO_RESPONSE_PACKET_LENGTH = 8
    if '@' in target:
        LOG.warn(f"sTorResolve failed invalid hostname {target}")
        return ''
    target = target.strip('/')
    seb = b"\x04\xf0\x00\x00\x00\x00\x00\x01\x00"
    seb += bytes(target, 'US-ASCII') + b"\x00"
    assert len(seb) == 10 + len(target), str(len(seb)) + repr(seb)

#    LOG.debug(f"0 Sending {len(seb)} to The TOR proxy {seb}")

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((sHost, iPort))

    sock.settimeout(SOCK_TIMEOUT_SECONDS)
    oRet = sock.sendall(seb) # noqa

    i = 0
    data = ''
    while i < SOCK_TIMEOUT_TRIES:
        i += 1
        time.sleep(3)
        lReady = select.select([sock.fileno()], [], [],
                               SOCK_TIMEOUT_SECONDS)
        if not lReady[0]: continue
        try:
            flags=socket.MSG_WAITALL
            data = sock.recv(MAX_INFO_RESPONSE_PACKET_LENGTH, flags)
        except socket.timeout:
            LOG.warn(f"4 The TOR proxy {(sHost, iPort)}" \
                +" didnt reply in " + str(SOCK_TIMEOUT_SECONDS) + " sec."
                +" #" +str(i))
        except Exception as e:
            LOG.error("4 The TOR proxy " \
                +repr((sHost, iPort)) \
                +" errored with " + str(e)
                +" #" +str(i))
            sock.close()
            return ''
        else:
            if len(data) > 0: break

    if len(data) == 0:
        if i > SOCK_TIMEOUT_TRIES:
            sLabel = "5 No reply #"
        else:
            sLabel = "5 No data #"
        LOG.warn(f"sTorResolve: {sLabel} {i} on {sHost}:{iPort}")
        sock.close()
        return ''

    assert len(data) >= 8
    packet_sf = data[1]
    if packet_sf == 90:
        # , "%d" % packet_sf
        assert f"{packet_sf}" == "90", f"packet_sf = {packet_sf}"
        return f"{data[4]}.{data[5]}.{data[6]}.{data[7]}"
    else:
        # 91
        LOG.warn(f"tor-resolve failed for {target} on {sHost}:{iPort}")

    os.system(f"tor-resolve -4 {target} > /tmp/e 2>/dev/null")
#    os.system("strace tor-resolve -4 "+target+" 2>&1|grep '^sen\|^rec'")

    return ''

def getaddrinfo(sHost, sPort):
    # do this the explicit way = Ive seen the compact connect fail
    # >>> sHost, sPort = 'l27.0.0.1', 33446
    # >>> sock.connect((sHost, sPort))
    # socket.gaierror: [Errno -2] Name or service not known
    try:
        lElts = socket.getaddrinfo(sHost, int(sPort), socket.AF_INET)
        lElts = list(filter(lambda elt: elt[1] == socket.SOCK_DGRAM, lElts))
        assert len(lElts) == 1, repr(lElts)
        lPair = lElts[0][-1]
        assert len(lPair) == 2, repr(lPair)
        assert type(lPair[1]) == int, repr(lPair)
    except (socket.gaierror, OSError, BaseException) as e:
        LOG.error(e)
        return None
    return lPair

def icheck_torrc(sFile, oArgs):
    l = open(sFile, 'rt').readlines()
    a = {}
    for elt in l:
        elt = elt.strip()
        if not elt or ' ' not in elt: continue
        (k, v,) = elt.split(' ', 1)
        a[k] = v
    keys = a

    if 'HashedControlPassword' not in keys:
        LOG.info('Add HashedControlPassword for security')
        print('run: tor --hashcontrolpassword <TopSecretWord>')
    if 'ExcludeExitNodes' in keys:
        elt = 'BadNodes.ExcludeExitNodes.BadExit'
        LOG.warn(f"Remove ExcludeNodes and move then to {oArgs.bad_nodes}")
        print(f"move to the {elt} section as a list")
    if 'GuardNodes' in keys:
        elt = 'GoodNodes.GuardNodes'
        LOG.warn(f"Remove GuardNodes and move then to {oArgs.good_nodes}")
        print(f"move to the {elt} section as a list")
    if 'ExcludeNodes' in keys:
        elt = 'BadNodes.ExcludeNodes.BadExit'
        LOG.warn(f"Remove ExcludeNodes and move then to {oArgs.bad_nodes}")
        print(f"move to the {elt} section as a list")
    if 'ControlSocket' not in keys and os.path.exists('/run/tor/control'):
        LOG.info('Add ControlSocket /run/tor/control for us')
        print('ControlSocket /run/tor/control GroupWritable RelaxDirModeCheck')
    if 'UseMicrodescriptors' not in keys or keys['UseMicrodescriptors'] != '1':
        LOG.info('Add UseMicrodescriptors 0 for us')
        print('UseMicrodescriptors 0')
    if 'AutomapHostsSuffixes' not in keys:
        LOG.info('Add AutomapHostsSuffixes for onions')
        print('AutomapHostsSuffixes .exit,.onion')
    if 'AutoMapHostsOnResolve' not in keys:
        LOG.info('Add AutoMapHostsOnResolve for onions')
        print('AutoMapHostsOnResolve 1')
    if 'VirtualAddrNetworkIPv4' not in keys:
        LOG.info('Add VirtualAddrNetworkIPv4 for onions')
        print('VirtualAddrNetworkIPv4 172.16.0.0/12')
    return 0

def lExitExcluder(oArgs, iPort=9051, log_level=10):
    """
    https://raw.githubusercontent.com/nusenu/noContactInfo_Exit_Excluder/main/exclude_noContactInfo_Exits.py
    """
    if not stem:
        LOG.warn('please install the stem Python package')
        return ''
    LOG.debug('lExcludeExitNodes')

    try:
        controller = oGetStemController(log_level=log_level)
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

if __name__ == '__main__':
    target = 'duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad'
    controller = oGetStemController(log_level=10)
    lIntroductionPoints(controller, [target], itimeout=120)
