# -*- mode: python; indent-tabs-mode: nil; py-indent-offset: 4; coding: utf-8 -*-
import os
import sys
from ctypes import CDLL

# You need a libs directory beside this directory 
# and you need to link your libtoxcore.so and libtoxav.so
# and libtoxencryptsave.so into ../libs/
# Link all 3 to libtoxcore.so if you have only libtoxcore.so
try:
    import utils.util as util
    sLIBS_DIR = util.get_libs_directory()
except ImportError:
    sLIBS_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)),
                             'libs')
    
class LibToxCore:

    def __init__(self):
        platform = sys.platform
        if platform == 'win32':
            libtoxcore = 'libtox.dll'
        elif platform == 'darwin':
            libtoxcore = 'libtoxcore.dylib'
        else:
            libtoxcore = 'libtoxcore.so'

        # libtoxcore and libsodium may be installed in your os
        # give libs/ precedence
        libFile = os.path.join(sLIBS_DIR, libtoxcore)
        assert os.path.isfile(libFile), libFile
        if os.path.isfile(libFile):
            self._libtoxcore = CDLL(libFile)
        else:
            self._libtoxcore = CDLL(libtoxcore)

    def __getattr__(self, item):
        return self._libtoxcore.__getattr__(item)

class LibToxAV:

    def __init__(self):
        platform = util.get_platform()
        if platform == 'Windows':
            # on Windows av api is in libtox.dll
            self._libtoxav = CDLL(os.path.join(sLIBS_DIR, 'libtox.dll'))
        elif platform == 'Darwin':
            self._libtoxav = CDLL('libtoxcore.dylib')
        else:
            libFile = os.path.join(sLIBS_DIR, 'libtoxav.so')
            assert os.path.isfile(libFile), libFile
            if os.path.isfile(libFile):
                self._libtoxav = CDLL(libFile)
            else:
                self._libtoxav = CDLL('libtoxav.so')

    def __getattr__(self, item):
        return self._libtoxav.__getattr__(item)

# figure out how to see if we have a combined library

class LibToxEncryptSave:

    def __init__(self):
        platform = sys.platform
        if platform == 'win32':
            # on Windows profile encryption api is in libtox.dll
            self._lib_tox_encrypt_save = CDLL(os.path.join(sLIBS_DIR, 'libtox.dll'))
        elif platform == 'darwin':
            self._lib_tox_encrypt_save = CDLL('libtoxcore.dylib')
        else:
            libFile = os.path.join(sLIBS_DIR, 'libtoxencryptsave.so')
            assert os.path.isfile(libFile), libFile
            if os.path.isfile(libFile):
                self._lib_tox_encrypt_save = CDLL(libFile)
            else:
                self._lib_tox_encrypt_save = CDLL('libtoxencryptsave.so')

    def __getattr__(self, item):
        return self._lib_tox_encrypt_save.__getattr__(item)

# figure out how to see if we have a combined library
