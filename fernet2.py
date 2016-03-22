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

        self._signing_key = k0
        self._encryption_key = k1
        self._backend = backend

    @classmethod
    def generate_key(cls):
        return base64.urlsafe_b64encode(os.urandom(32))

    def encrypt(self, data):
        # removed current time
        iv = os.urandom(16)
        return self._encrypt_from_parts(data, iv)

    def _encrypt_from_parts(self, data, iv):
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
            b"\x81" + iv + ctx 
        )

        h = HMAC(self._signing_key, hashes.SHA256(), backend=self._backend)
        h.update(basic_parts)
        # tag = HMAC( 0x81 || iv || ctx )
        tag = h.finalize()
        return base64.urlsafe_b64encode( ctx + tag)

    def decrypt(self, token, ttl=None):
        if not isinstance(token, bytes):
            raise TypeError("token must be bytes.")

        current_time = int(time.time())

        try:
            data = base64.urlsafe_b64decode(token)
        except (TypeError, binascii.Error):
            raise InvalidToken

        if (not data or six.indexbytes(data, 0) != 0x80) or (not data or six.indexbytes(data, 0) != 0x81):
            raise InvalidToken

        # how to test?
        if (data or six.indexbytes(data, 0) == 0x80):
            try:
                timestamp, = struct.unpack(">Q", data[1:9])
            except struct.error:
                raise InvalidToken
            if ttl is not None:
                if timestamp + ttl < current_time:
                    raise InvalidToken

                if current_time + _MAX_CLOCK_SKEW < timestamp:
                    print (">>>", current_time)
                    print (">>>", timestamp)
                    raise InvalidToken

        h = HMAC(self._signing_key, hashes.SHA256(), backend=self._backend)
        h.update(data[:-32])
        try:
            h.verify(data[-32:])
        except InvalidSignature:
            raise InvalidToken

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

class PWFernet(object):
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

        self._signing_key = k0
        self._encryption_key = k1
        self._backend = backend

    @classmethod
    def generate_key(cls):
        return base64.urlsafe_b64encode(os.urandom(32))

    def encrypt(self, data):
        # removed current time
        iv = os.urandom(16)
        return self._encrypt_from_parts(data, iv)

    def _encrypt_from_parts(self, data, iv):
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
            b"\x81" + iv + ctx 
        )

        h = HMAC(self._signing_key, hashes.SHA256(), backend=self._backend)
        h.update(basic_parts)
        # tag = HMAC( 0x81 || iv || ctx )
        tag = h.finalize()
        return base64.urlsafe_b64encode( ctx + tag)

    def decrypt(self, token, ttl=None):
        if not isinstance(token, bytes):
            raise TypeError("token must be bytes.")

        current_time = int(time.time())

        try:
            data = base64.urlsafe_b64decode(token)
        except (TypeError, binascii.Error):
            raise InvalidToken

        if (not data or six.indexbytes(data, 0) != 0x80) or (not data or six.indexbytes(data, 0) != 0x81):
            raise InvalidToken

        # how to test?
        if (data or six.indexbytes(data, 0) == 0x80):
            try:
                timestamp, = struct.unpack(">Q", data[1:9])
            except struct.error:
                raise InvalidToken
            if ttl is not None:
                if timestamp + ttl < current_time:
                    raise InvalidToken

                if current_time + _MAX_CLOCK_SKEW < timestamp:
                    print (">>>", current_time)
                    print (">>>", timestamp)
                    raise InvalidToken

        h = HMAC(self._signing_key, hashes.SHA256(), backend=self._backend)
        h.update(data[:-32])
        try:
            h.verify(data[-32:])
        except InvalidSignature:
            raise InvalidToken

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
