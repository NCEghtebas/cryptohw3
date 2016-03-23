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

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.hmac import HMAC


class InvalidToken(Exception):
    pass


_MAX_CLOCK_SKEW = 60


class Fernet2(object):
    def __init__(self, key, backend=None):
        if backend is None:
            backend = default_backend()

        key = base64.urlsafe_b64decode(key)
        if len(key) != 32:
            raise ValueError(
                "Fernet key must be 32 url-safe base64-encoded bytes."
            )

        h0 = HMAC(key, hashes.SHA256(), backend=backend)
        h1 = HMAC(key, hashes.SHA256(), backend=backend)
        # 
        h0 .update(b"0")
        h1 .update(b"1")
        k0 = h0.finalize()[:16]
        k1 = h1.finalize()[:16]

        #TODO fix   
        # self._f = Fernet1(secret.encode("ascii"), backend=backend)

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
        cxt = encryptor.update(padded_data) + encryptor.finalize()

        basic_parts = (
            b"\x81" + iv + ctx + adata
        )

        h = HMAC(self._signing_key, hashes.SHA256(), backend=self._backend)
        h.update(basic_parts)
        # tag = HMAC( 0x81 || iv || ctx )
        tag = h.finalize()
        return base64.urlsafe_b64encode( b"\x81" + iv + ctx + tag)

    def decrypt(self, token, ttl=None, adata=""):

        # TODO: if 80: 
            # call fernet decrypt
            # create global fernet obj in init

        # elif 81:
        if not isinstance(token, bytes):
            raise TypeError("token must be bytes.")

        try:
            data = base64.urlsafe_b64decode(token)
        except (TypeError, binascii.Error):
            raise InvalidToken

        if (not data or six.indexbytes(data, 0) != 0x80) or (not data or six.indexbytes(data, 0) != 0x81):
            raise InvalidToken

        

        h = HMAC(self._signing_key, hashes.SHA256(), backend=self._backend)
        h.update(data[:-32])
        try:
            h.verify(data[-32:])
        except InvalidSignature:
            raise InvalidToken

        # TODO: get associated data
        # check for correct associated data

        iv = data[9:25]
        ciphertext = data[25:-32]
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
        # else
        # error

class PWFernet(object):
    def __init__(self, password, backend=None):
        if backend is None:
            backend = default_backend()

        self._backend = backend
        self._password = password
    
    def gen_encrypt_key(self, salt, password):
        backend = default_backend()

        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000, backend=backend)
        key = kdf.derive(password)

        signing_key = key[:16]
        encryption_key = key[16:]
        return signing_key, encryption_key

    def encrypt(self, data, adata=""):
        salt = os.urandom(16)
        signing_key, encryption_key = gen_encrypt_key(salt, self._password)
        return self._encrypt_from_parts(data, salt, signing_key, encryption_key)

    def _encrypt_from_parts(self, data, adata="", salt, signing_key, encryption_key ):
        if not isinstance(data, bytes):
            raise TypeError("data must be bytes.")

        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(data) + padder.finalize()
        encryptor = Cipher(
            algorithms.AES(encryption_key), modes.CBC("0"*16), self._backend
        ).encryptor()
        # ctx = AES( iv || msg )
        cxt = encryptor.update(padded_data) + encryptor.finalize()

        basic_parts = (
            b"\x82" + salt + ctx + adata
        )

        h = HMAC(signing_key, hashes.SHA256(), backend=self._backend)
        h.update(basic_parts)
        # tag = HMAC( 0x81 || iv || ctx )
        tag = h.finalize()
        return base64.urlsafe_b64encode( b"\x82" + salt + ctx + tag )


    def decrypt(self, token, ttl=None):
        if not isinstance(token, bytes):
            raise TypeError("token must be bytes.")

        try:
            data = base64.urlsafe_b64decode(token)
        except (TypeError, binascii.Error):
            raise InvalidToken

        if not data or six.indexbytes(data, 0) != 0x82:
            raise InvalidToken


        h = HMAC(self._signing_key, hashes.SHA256(), backend=self._backend)
        h.update(data[:-32])
        try:
            h.verify(data[-32:])
        except InvalidSignature:
            raise InvalidToken


        salt = data[9:25]

        # create two keys from salt and decrypt message
        ciphertext = data[25:-32]
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
