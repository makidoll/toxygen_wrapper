# -*- mode: python; indent-tabs-mode: nil; py-indent-offset: 4; coding: utf-8 -*-

import os
import sys
import logging
from io import BytesIO
import urllib
import traceback

global LOG
LOG = logging.getLogger('app.'+'ts')

try:
    import pycurl
except ImportError:
    pycurl = None
try:
    import requests
except ImportError:
    requests = None

lNO_PROXY = ['localhost', '127.0.0.1']
CONNECT_TIMEOUT = 20.0

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

def pick_up_proxy_from_environ():
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
    else:
        retval['proxy_host'] = ''
        retval['proxy_port'] = ''
        retval['proxy_type'] = 0
        retval['udp_enabled'] = True
    return retval

def download_url(url, settings=None):
    if not bAreWeConnected(): return ''

    if settings is None:
        settings = pick_up_proxy_from_environ()

    if pycurl:
        LOG.debug('Downloading with pycurl: ' + str(url))
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
            LOG.info('nodes loaded with pycurl: ' + str(url))
            return result
        except Exception as ex:
            LOG.error('TOX Downloading error with pycurl: ' + str(ex))
            LOG.error('\n' + traceback.format_exc())
            # drop through

    if requests:
        LOG.debug('Downloading with requests: ' + str(url))
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
            LOG.info('nodes loaded with requests: ' + str(url))
            return result
        except Exception as ex:
            LOG.error('TOX Downloading error with requests: ' + str(ex))
            # drop through

    if not settings['proxy_type']:  # no proxy
        LOG.debug('Downloading with urllib no proxy: ' + str(url))
        try:
            req = urllib.request.Request(url)
            req.add_header('Content-Type', 'application/json')
            response = urllib.request.urlopen(req)
            result = response.read()
            LOG.info('nodes loaded with no proxy: ' + str(url))
            return result
        except Exception as ex:
            LOG.error('TOX Downloading ' + str(ex))
        return ''

    return ''

