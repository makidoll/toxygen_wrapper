# -*- mode: python; indent-tabs-mode: nil; py-indent-offset: 4; coding: utf-8 -*-

try:
    from tox_wrapper import libtox
    import tox_wrapper.toxencryptsave_enums_and_consts as enum
except:
    import libtox
    import toxencryptsave_enums_and_consts as enum

from typing import Union, Callable
from ctypes import (ArgumentError, byref, c_bool, c_char_p, c_int, c_size_t,
                    create_string_buffer, Array)
def ToxError(ArgumentError): pass
    
class ToxEncryptSave:

    def __init__(self):
        self.libtoxencryptsave = libtox.LibToxEncryptSave()

    def is_data_encrypted(self, data: bytes) -> bool:
        """
        Checks if given data is encrypted
        """
        func = self.libtoxencryptsave.tox_is_data_encrypted
        func.restype = c_bool
        result = func(c_char_p(bytes(data)))
        return bool(result)

    def pass_encrypt(self, data: bytes, password: Union[str,bytes]) -> bytes:
        """
        Encrypts the given data with the given password.

        :return: output array
        """
        out = create_string_buffer(len(data) + enum.TOX_PASS_ENCRYPTION_EXTRA_LENGTH)
        tox_err_encryption = c_int()
        assert password
        if type(password) != bytes:
            password = bytes(password, 'utf-8')
        self.libtoxencryptsave.tox_pass_encrypt(c_char_p(data),
                                                c_size_t(len(data)),
                                                c_char_p(password),
                                                c_size_t(len(password)),
                                                out,
                                                byref(tox_err_encryption))
        tox_err_encryption = tox_err_encryption.value
        if tox_err_encryption == enum.TOX_ERR_ENCRYPTION['OK']:
            return bytes(out[:])
        if tox_err_encryption == enum.TOX_ERR_ENCRYPTION['NULL']:
            raise ArgumentError('Some input data, or maybe the output pointer, was null.')
        if tox_err_encryption == enum.TOX_ERR_ENCRYPTION['KEY_DERIVATION_FAILED']:
            raise RuntimeError('The crypto lib was unable to derive a key from the given passphrase, which is usually a'
                               ' lack of memory issue. The functions accepting keys do not produce this error.')
        if tox_err_encryption == enum.TOX_ERR_ENCRYPTION['FAILED']:
            raise RuntimeError('The encryption itself failed.')
        raise ToxError('The function did not return OK.')

    def pass_decrypt(self, data: bytes, password: Union[str,bytes]) -> bytes:
        """
        Decrypts the given data with the given password.

        :return: output array
        """
        out = create_string_buffer(len(data) - enum.TOX_PASS_ENCRYPTION_EXTRA_LENGTH)
        tox_err_decryption = c_int()
        assert password
        if type(password) != bytes:
            password = bytes(password, 'utf-8')
        self.libtoxencryptsave.tox_pass_decrypt(c_char_p(bytes(data)),
                                                c_size_t(len(data)),
                                                c_char_p(password),
                                                c_size_t(len(password)),
                                                out,
                                                byref(tox_err_decryption))
        tox_err_decryption = tox_err_decryption.value
        if tox_err_decryption == enum.TOX_ERR_DECRYPTION['OK']:
            return bytes(out[:])
        if tox_err_decryption == enum.TOX_ERR_DECRYPTION['NULL']:
            raise ArgumentError('Some input data, or maybe the output pointer, was null.')
        if tox_err_decryption == enum.TOX_ERR_DECRYPTION['INVALID_LENGTH']:
            raise ArgumentError('The input data was shorter than TOX_PASS_ENCRYPTION_EXTRA_LENGTH bytes')
        if tox_err_decryption == enum.TOX_ERR_DECRYPTION['BAD_FORMAT']:
            raise ArgumentError('The input data is missing the magic number (i.e. wasn\'t created by this module, or is'
                                ' corrupted)')
        if tox_err_decryption == enum.TOX_ERR_DECRYPTION['KEY_DERIVATION_FAILED']:
            raise RuntimeError('The crypto lib was unable to derive a key from the given passphrase, which is usually a'
                               ' lack of memory issue. The functions accepting keys do not produce this error.')
        if tox_err_decryption == enum.TOX_ERR_DECRYPTION['FAILED']:
            raise RuntimeError('The encrypted byte array could not be decrypted. Either the data was corrupt or the '
                               'password/key was incorrect.')
        raise ToxError('The function did not return OK.')
