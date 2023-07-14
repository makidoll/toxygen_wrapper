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

yKNOWN_ONIONS = """
  - facebookwkhpilnemxj7asaniu7vnjjbiltxjqhye3mhbshg7kx5tfyd # facebook
  - duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad # ddg
  - zkaan2xfbuxia2wpf7ofnkbz6r5zdbbvxbunvp5g2iebopbfc4iqmbad # hks
"""
#  grep -B 1 '<li><a href="' /tmp/tor.html |sed -e 's/<li><a href="http:../  - /' -e 's/.onion.*//' -e 's/<li id=./  # /' -e 's/".*//' -e '/^--/d' -e '/<li id/d'
# This will slow things down 1-2 min each
yKNOWN_ONIONS_TOR = """
  # 2019.www.torproject.org
  - jqyzxhjk6psc6ul5jnfwloamhtyh7si74b4743k2qgpskwwxrzhsxmad
  # api.donate.torproject.org
  - rbi3fpvpz4vlrx67scoqef2zxz7k4xyiludszg655favvkygjmhz6wyd
  # archive.torproject.org
  - uy3qxvwzwoeztnellvvhxh7ju7kfvlsauka7avilcjg7domzxptbq7qd
  # aus1.torproject.org
  - ot3ivcdxmalbsbponeeq5222hftpf3pqil24q3s5ejwo5t52l65qusid
  # aus2.torproject.org
  - b5t7emfr2rn3ixr4lvizpi3stnni4j4p6goxho7lldf4qg4hz5hvpqid
  # blog.torproject.org
  - pzhdfe7jraknpj2qgu5cz2u3i4deuyfwmonvzu5i3nyw4t4bmg7o5pad
  # bridges.torproject.org
  - yq5jjvr7drkjrelzhut7kgclfuro65jjlivyzfmxiq2kyv5lickrl4qd
  # cloud.torproject.org
  - ui3cpcohcoko6aydhuhlkwqqtvadhaflcc5zb7mwandqmcal7sbwzwqd
  # collector.torproject.org
  - pgmrispjerzzf2tdzbfp624cg5vpbvdw2q5a3hvtsbsx25vnni767yad
  # collector2.torproject.org
  - 3srlmjzbyyzz62jvdfqwn5ldqmh6mwnqxre2zamxveb75uz2qrqkrkyd
  # community.torproject.org
  - xmrhfasfg5suueegrnc4gsgyi2tyclcy5oz7f5drnrodmdtob6t2ioyd
  # consensus-health.torproject.org
  - tkskz5dkjel4xqyw5d5l3k52kgglotwn6vgb5wrl2oa5yi2szvywiyid
  # crm.torproject.org
  - 6ojylpznauimd2fga3m7g24vd7ebkzlemxdprxckevqpzs347ugmynqd
  # deb.torproject.org
  - apow7mjfryruh65chtdydfmqfpj5btws7nbocgtaovhvezgccyjazpqd
  # dev.crm.torproject.org
  - eewp4iydzyu2a5d6bvqadadkozxdbhsdtmsoczu2joexfrjjsheaecad
  # dist.torproject.org
  - scpalcwstkydpa3y7dbpkjs2dtr7zvtvdbyj3dqwkucfrwyixcl5ptqd
  # donate-api.torproject.org
  - lkfkuhcx62yfvzuz5o3ju4divuf4bsh2bybwd3oierq47kyp2ig2gvid
  # donate.torproject.org
  - yoaenchicimox2qdc47p36zm3cuclq7s7qxx6kvxqaxjodigfifljqqd
  # exonerator.torproject.org
  - pm46i5h2lfewyx6l7pnicbxhts2sxzacvsbmqiemqaspredf2gm3dpad
  # extra.torproject.org
  - kkr72iohlfix5ipjg776eyhplnl2oiv5tz4h2y2bkhjix3quafvjd5ad
  # gettor.torproject.org
  - ueghr2hzndecdntou33mhymbbxj7pir74nwzhqr6drhxpbz3j272p4id
  # git.torproject.org
  - xtlfhaspqtkeeqxk6umggfbr3gyfznvf4jhrge2fujz53433i2fcs3id
  # gitlab.torproject.org
  - eweiibe6tdjsdprb4px6rqrzzcsi22m4koia44kc5pcjr7nec2rlxyad
  # gitweb.torproject.org
  - gzgme7ov25seqjbphab4fkcph3jkobfwwpivt5kzbv3kqx2y2qttl4yd
  # grafana1.torproject.org
  - 7zjnw5lx2x27rwiocxkqdquo7fawj46mf2wiu2l7e6z6ng6nivmdxnad
  # grafana2.torproject.org
  - f3vd6fyiccuppybkxiblgigej3pfvvqzjnhd3wyv7h4ee5asawf2fhqd
  # ircbouncer.torproject.org
  - moz5kotsnjony4oxccxfo4lwk3pvoxmdoljibhgoonzgzjs5oemtjmqd
  # metabase.metrics.torproject.org
  - gr5pseamigereei4c6654hafzhid5z2c3oqzn6cfnx7yfyelt47znhad
  # metrics.torproject.org
  - hctxrvjzfpvmzh2jllqhgvvkoepxb4kfzdjm6h7egcwlumggtktiftid
  # moat.torproject.org
  - z7m7ogzdhu43nosvjtsuplfmuqa3ge5obahixydhmzdox6owwxfoxzid
  # nagios.torproject.org
  - w6vizvw4ckesva5fvlkrepynemxdq6pgo5sh4r76ec6msq5notkhqryd
  # newsletter.torproject.org
  - a4ygisnerpgtc5ayerl22pll6cls3oyj54qgpm7qrmb66xrxts6y3lyd
  # nightlies.tbb.torproject.org
  - umj4zbqdfcyevlkgqgpq6foxk3z75zzxsbgt5jqmfxofrbrjh3crbnad
  # nyx.torproject.org
  - 3ewfgrt4gzfccp6bnquhqb266r3zepiqpnsk3falwygkegtluwuyevid
  - xao2lxsmia2edq2n5zxg6uahx6xox2t7bfjw6b5vdzsxi7ezmqob6qid
  - dud2sxm6feahhuwj4y4lzktduy7v3qpaqsfkggtj2ojmzathttkegoid
  # openpgpkey.torproject.org
  - 2yldcptk56shc7lwieozoglw3t5ghty7m6mf2faysvfnzccqavbu2mad
  # people.torproject.org
  - 5ecey6oe4rocdsfoigr4idu42cecm2j7zfogc3xc7kfn4uriehwrs6qd
  # prometheus1.torproject.org
  - ydok5jiruh3ak6hcfdlm2g7iuraaxcomeckj2nucjsxif6qmrrda2byd
  # prometheus2.torproject.org
  - vyo6yrqhl3by7d6n5t6hjkflaqbarjpqjnvapr5u5rafk4imnfrmcjyd
  # rbm.torproject.org
  - nkuz2tpok7ctwd5ueer5bytj3bm42vp7lgjcsnznal3stotg6vyaakyd
  # research.torproject.org
  - xhqthou6scpfnwjyzc3ekdgcbvj76ccgyjyxp6cgypxjlcuhnxiktnqd
  # review.torproject.net
  - zhkhhhnppc5k6xju7n25rjba3wuip73jnodicxl65qdpchrwvvsilcyd
  # rpm.torproject.org
  - 4ayyzfoh5qdrokqaejis3rdredhvf22n3migyxfudpkpunngfc7g4lqd
  # snowflake.torproject.org
  - oljlphash3bpqtrvqpr5gwzrhroziw4mddidi5d2qa4qjejcbrmoypqd
  # spec.torproject.org
  - i3xi5qxvbrngh3g6o7czwjfxwjzigook7zxzjmgwg5b7xnjcn5hzciad
  # staging-api.donate.torproject.org
  - vorwws6g6mx23djlznmlqva4t5olulpnet6fxyiyytcu5dorp3fstdqd
  # staging.crm.torproject.org
  - pt34uujusar4arrvsqljndqlt7tck2d5cosaav5xni4nh7bmvshyp2yd
  # staging.donate-api.torproject.org
  - 7niqsyixinnhxvh33zh5dqnplxnc2yd6ktvats3zmtbbpzcphpbsa6qd
  # status.torproject.org
  - eixoaclv7qvnmu5rolbdwba65xpdiditdoyp6edsre3fitad777jr3ad
  # stem.torproject.org
  - mf34jlghauz5pxjcmdymdqbe5pva4v24logeys446tdrgd5lpsrocmqd
  # styleguide.torproject.org
  - 7khzpw47s35pwo3lvtctwf2szvnq3kgglvzc22elx7of2awdzpovqmqd
  # submission.torproject.org
  - givpjczyrb5jjseful3o5tn3tg7tidbu4gydl4sa5ekpcipivqaqnpad
  # support.torproject.org
  - rzuwtpc4wb3xdzrj3yeajsvm3fkq4vbeubm2tdxaqruzzzgs5dwemlad
  # survey.torproject.org
  - eh5esdnd6fkbkapfc6nuyvkjgbtnzq2is72lmpwbdbxepd2z7zbgzsqd
  # svn-archive.torproject.org
  - b63iq6es4biaawfilwftlfkw6a6putogxh4iakei2ioppb7dsfucekyd
  # tb-manual.torproject.org
  - dsbqrprgkqqifztta6h3w7i2htjhnq7d3qkh3c7gvc35e66rrcv66did
  # test-api.donate.torproject.org
  - wiofesr5qt2k7qrlljpk53isgedxi6ddw6z3o7iay2l7ne3ziyagxaid
  # test-data.tbb.torproject.org
  - umbk3kbgov4ekg264yulvbrpykfye7ohguqbds53qn547mdpt6o4qkad
  # test.crm.torproject.org
  - a4d52y2erv4eijii66cpnyqn7rsnnq3gmtrsdxzt2laoutvu4gz7fwid
  # test.donate-api.torproject.org
  - i4zhrn4md3ucd5dfgeo5lnqd3jy2z2kzp3lt4tdisvivzoqqtlrymkid
  # www
  - tttyx2vwp7ihml3vkhywwcizv6nbwrikpgeciy3qrow7l7muak2pnhad
  # www.torproject.org
  - 2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid
"""

# we check these each time but we got them by sorting bad relays
# in the wild we'll keep a copy here so we can avoid restesting
yKNOWN_NODNS = """
  - 0x0.is
  - a9.wtf
  - apt96.com
  - axims.net
  - backup.spekadyon.org
  - dfri.se
  - dotsrc.org
  - dtf.contact
  - ezyn.de
  - for-privacy.net
  - galtland.network
  - heraldonion.org
  - interfesse.net
  - kryptonit.org
  - linkspartei.org
  - mkg20001.io
  - nicdex.com
  - nx42.de
  - pineapple.cx
  - privacylayer.xyz
  - privacysvcs.net
  - prsv.ch
  - sebastian-elisa-pfeifer.eu
  - thingtohide.nl
  - tor-exit-2.aa78i2efsewr0neeknk.xyz
  - tor-exit-3.aa78i2efsewr0neeknk.xyz
  - tor.dlecan.com
  - tor.skankhunt42.pw
  - transliberation.today
  - tuxli.org
  - unzane.com
  - verification-for-nusenu.net
  - www.defcon.org
"""
#  - aklad5.com
#  - artikel5ev.de
#  - arvanode.net
#  - dodo.pm
#  - erjan.net
#  - galtland.network
#  - lonet.sh
#  - moneneis.de
#  - olonet.sh
#  - or-exit-2.aa78i2efsewr0neeknk.xyz
#  - or.wowplanet.de
#  - ormycloud.org
#  - plied-privacy.net
#  - rivacysvcs.net
#  - redacted.org
#  - rofl.cat
#  - sv.ch
#  - tikel10.org
#  - tor.wowplanet.de
#  - torix-relays.org
#  - tse.com
#  - w.digidow.eu
#  - w.cccs.de

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
    # stem.util.log.Runlevel = 'DEBUG' = 20 # log_level

    if os.path.exists(sock_or_pair):
        LOG.info(f"controller from socket {sock_or_pair}")
        controller = Controller.from_socket_file(path=sock_or_pair)
    else:
        if type(sock_or_pair) == int:
            port = sock_or_pair
        elif ':' in sock_or_pair:
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
        except stem.DescriptorUnavailable as e:
          LOG.error(e)
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
