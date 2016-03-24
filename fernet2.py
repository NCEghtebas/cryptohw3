# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

import base64
import binascii
import os
import struct
import time

import six
from fernet import Fernet
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

class InvalidToken(Exception):
    pass


_MAX_CLOCK_SKEW = 60


class Fernet2(object):
    def __init__(self, key, backend=None):
        if backend is None:
            backend = default_backend()

        # initialize a fernet object
        self._f = Fernet(key, backend=backend)

        key = base64.urlsafe_b64decode(key)
        if len(key) != 32:
            raise ValueError(
                "Fernet2 key must be 32 url-safe base64-encoded bytes."
            )

        h0 = HMAC(key, hashes.SHA256(), backend=backend)
        h1 = HMAC(key, hashes.SHA256(), backend=backend)
        # 
        h0 .update(b"0")
        h1 .update(b"1")
        k0 = h0.finalize()[:16]
        k1 = h1.finalize()[:16]



        self._signing_key = k0
        self._encryption_key = k1
        self._backend = backend

    @classmethod
    def generate_key(cls):
        return base64.urlsafe_b64encode(os.urandom(32))

    def encrypt(self, data, adata=""):
        # removed current time
        iv = os.urandom(16)
        return self._encrypt_from_parts(data, iv, adata)

    def _encrypt_from_parts(self, data, iv, adata=""):
        if not isinstance(data, bytes):
            raise TypeError("data must be bytes.")

        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(data) + padder.finalize()
        encryptor = Cipher(
            algorithms.AES(self._encryption_key), modes.CBC(iv), self._backend
        ).encryptor()
        # ctx = AES( iv || msg )
        ctx = encryptor.update(padded_data) + encryptor.finalize()
        basic_parts = (
            b"\x81" + iv + ctx
        )
        # print(str(len(basic_parts)), "basic_parts_len == ", basic_parts)
        print("iv = " + str(len(iv)), iv)
        # print(str(len(ctx)), "ctx == ", ctx)
        # print("adata == " , len(adata), adata)
        h = HMAC(self._signing_key, hashes.SHA256(), backend=self._backend)
        h.update(basic_parts+adata)
        # tag = HMAC( 0x81 || iv || ctx )
        tag = h.finalize()
        # print("tag = " , len(tag))
        return base64.urlsafe_b64encode( basic_parts + tag)

    def decrypt(self, token, ttl=None, adata=""):
        if not isinstance(token, bytes):
            raise TypeError("token must be bytes.")
        print("token = " , token)

        try:
            data = base64.urlsafe_b64decode(token)
        except (TypeError, binascii.Error):
            raise InvalidToken
        print("data = " , data)
        if data == 0x80 or six.indexbytes(data, 0) == 0x80:
            print("80 version\n")
            # TODO: if 80:
            return self._f.decrypt(self, token, ttl)
        elif data == 0x81 or six.indexbytes(data, 0) == 0x81:
            print("81 version\n")

            ############ VERIFYING adata
            # print("data = " + str(len(data)), data)
            h = HMAC(self._signing_key, hashes.SHA256(), backend=self._backend)
            basic_parts = data[:-32]
            basic_adata = basic_parts + base64.urlsafe_b64decode(base64.urlsafe_b64encode(adata))
            # print("==================", base64.urlsafe_b64decode(base64.urlsafe_b64encode(adata)))
            h.update(basic_adata)
            # print("basic_parts_len = " + str(len(basic_parts)), basic_parts)

            # print("basic_adata = " + str(len(basic_adata)), basic_adata)
            # print("adata = " , len(adata), adata)
            try:
                h.verify(data[-32:])
            except InvalidSignature:
                raise InvalidToken

            ################ signature stuff from fernet.py
            # h = HMAC(self._signing_key, hashes.SHA256(), backend=self._backend)
            # h.update(data[:-32]) # get everything from data except for last 32 bytes
            # # print(h.update(data[:-32]))
            # try:
            #     # verifying signature with the last 32 bytes
            #     h.verify(data[-32:])
            # except InvalidSignature:
            #     raise InvalidToken
            ################ END-OF signature stuff from fernet.py
            # TODO: get associated data
            # check for correct associated data

            # iv = data[9:25]
            iv = data[1:17]
            print("iv == " + str(len(iv)), iv)
            # find out associated data in data
            # try satement, if adata_to_get = adata
            ciphertext = data[17:-32]
            decryptor = Cipher(
                algorithms.AES(self._encryption_key), modes.CBC(iv), self._backend
            ).decryptor()
            plaintext_padded = decryptor.update(ciphertext)
            try:
                plaintext_padded += decryptor.finalize()
            except ValueError:
                raise InvalidToken
            unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()

            unpadded = unpadder.update(plaintext_padded)
            try:
                unpadded += unpadder.finalize()
            except ValueError:
                raise InvalidToken
            return unpadded

        else:
            raise InvalidToken


class PWFernet(object):
    def __init__(self, password, backend=None):
        if backend is None:
            backend = default_backend()

        self._backend = backend
        self._password = password
    
    def gen_encrypt_key(self, salt = "", password = ""):
        backend = default_backend()

        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000, backend=backend)
        key = kdf.derive(password)

        signing_key = key[:16]
        encryption_key = key[16:]
        return signing_key, encryption_key

    def encrypt(self, data, adata=""):
        salt = os.urandom(16)
        print("salt == " + str(len(salt)), salt)
        signing_key, encryption_key = self.gen_encrypt_key(salt, self._password)
        return self._encrypt_from_parts(data, adata, salt, signing_key, encryption_key)

    def _encrypt_from_parts(self, data, adata="", salt = "", signing_key = "", encryption_key = ""):
        if not isinstance(data, bytes):
            raise TypeError("data must be bytes.")

        # print("signing_key = " + str(len(signing_key)), signing_key)
        # print("encryption_key = " + str(len(encryption_key)), encryption_key)
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(data) + padder.finalize()
        encryptor = Cipher(
            algorithms.AES(encryption_key), modes.CBC("0"*16), self._backend
        ).encryptor()
        # ctx = AES( iv || msg )
        ctx = encryptor.update(padded_data) + encryptor.finalize()

        basic_parts = (
            b"\x82" + salt + ctx
        )

        h = HMAC(signing_key, hashes.SHA256(), backend=self._backend)
        h.update(basic_parts + adata)
        # tag = HMAC( 0x81 || iv || ctx )
        tag = h.finalize()
        return base64.urlsafe_b64encode( basic_parts + tag )

    def decrypt(self, token, ttl=None, adata = ""):

        if not isinstance(token, bytes):
            raise TypeError("token must be bytes.")

        try:
            data = base64.urlsafe_b64decode(token)
        except (TypeError, binascii.Error):
            raise InvalidToken

        if data == 0x82 or six.indexbytes(data, 0) == 0x82:
            print("82 version\n")
            try:
                salt = data[1:17]
            except ValueError:
                raise InvalidToken

            print("salt == " + str(len(salt)), salt)
            # is this producing same signing and encrypt key? YES!
            signing_key, encryption_key = self.gen_encrypt_key(salt, self._password)
            # print("signing_key == " + str(len(signing_key)), signing_key)
            # print("encryption_key == " + str(len(encryption_key)), encryption_key)
            ############ VERIFYING adata
            # print("data = " + str(len(data)), data)
            h = HMAC(signing_key, hashes.SHA256(), backend=self._backend)
            basic_parts = data[:-32]
            basic_adata = basic_parts + base64.urlsafe_b64decode(base64.urlsafe_b64encode(adata))
            # print("==================", base64.urlsafe_b64decode(base64.urlsafe_b64encode(adata)))
            h.update(basic_adata)
            print("basic_parts_len = " + str(len(basic_parts)), basic_parts)

            print("basic_adata = " + str(len(basic_adata)), basic_adata)
            print("adata = " , len(adata), adata)
            try:
                h.verify(data[-32:])
            except InvalidSignature:
                raise InvalidToken

            ################ signature stuff from fernet.py
            # h = HMAC(self._signing_key, hashes.SHA256(), backend=self._backend)
            # h.update(data[:-32]) # get everything from data except for last 32 bytes
            # # print(h.update(data[:-32]))
            # try:
            #     # verifying signature with the last 32 bytes
            #     h.verify(data[-32:])
            # except InvalidSignature:
            #     raise InvalidToken
            ################ END-OF signature stuff from fernet.py
            # TODO: get associated data
            # check for correct associated data

            # iv = data[9:25]

            # find out associated data in data
            # try satement, if adata_to_get = adata
            ciphertext = data[17:-32]
            decryptor = Cipher(
                algorithms.AES(encryption_key), modes.CBC("0"*16), self._backend
            ).decryptor()
            plaintext_padded = decryptor.update(ciphertext)
            try:
                plaintext_padded += decryptor.finalize()
            except ValueError:
                raise InvalidToken
            unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()

            unpadded = unpadder.update(plaintext_padded)
            try:
                unpadded += unpadder.finalize()
            except ValueError:
                raise InvalidToken
            return unpadded

        else:
            raise InvalidToken







class MultiFernet(object):
    def __init__(self, fernets):
        fernets = list(fernets)
        if not fernets:
            raise ValueError(
                "MultiFernet requires at least one Fernet instance"
            )
        self._fernets = fernets

    def encrypt(self, msg):
        return self._fernets[0].encrypt(msg)

    def decrypt(self, msg, ttl=None):
        for f in self._fernets:
            try:
                return f.decrypt(msg, ttl)
            except InvalidToken:
                pass
        raise InvalidToken

