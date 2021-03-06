# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

import base64
import calendar
import json
import os
import time

import iso8601

import pytest
from sets import Set
import six
from fernet import Fernet
from fernet2 import PWFernet
from fernet2 import Fernet2, InvalidToken, MultiFernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.backends.interfaces import CipherBackend, HMACBackend
from cryptography.hazmat.primitives.ciphers import algorithms, modes

import cryptography_vectors


def json_parametrize(keys, filename):
    vector_file = cryptography_vectors.open_vector_file(
        os.path.join('fernet', filename), "r"
    )
    with vector_file:
        data = json.load(vector_file)
        return pytest.mark.parametrize(keys, [
            tuple([entry[k] for k in keys])
            for entry in data
        ])

def json_parametrize2(keys, filename):
    vector_file = cryptography_vectors.open_vector_file(
        os.path.join('fernet2', filename), "r"
    )
    with vector_file:
        data = json.load(vector_file)
        return pytest.mark.parametrize(keys, [
            tuple([entry[k] for k in keys])
            for entry in data
        ])

def test_default_backend():
    f = Fernet2(Fernet2.generate_key())
    assert f._backend is default_backend()


@pytest.mark.parametrize("backend", [default_backend()])
@pytest.mark.supported(
    only_if=lambda backend: backend.cipher_supported(
        algorithms.AES("\x00" * 32), modes.CBC("\x00" * 16)
    ),
    skip_message="Does not support AES CBC",
)
class TestFernet(object):
    """This is basically the tests given in test_fernet.py. This tests
    the bacward compatibility of the new Fernet2. 
    """

    ## This test will not work with new Fernet implementation. No need to worry about it.
    # @json_parametrize(
    #     ("secret", "now", "iv", "src", "token"), "generate.json",
    # )    
    # def test_generate(self, secret, now, iv, src, token, backend):
    #     f = Fernet2(secret.encode("ascii"), backend=backend)
    #     actual_token = f._encrypt_from_parts(
    #         src.encode("ascii"),
    #         calendar.timegm(iso8601.parse_date(now).utctimetuple()),
    #         b"".join(map(six.int2byte, iv))
    #     )
    #     assert actual_token == token.encode("ascii")

    @json_parametrize(
        ("secret", "now", "src", "ttl_sec", "token"), "verify.json",
    )
    def test_verify(self, secret, now, src, ttl_sec, token, backend,
                    monkeypatch):
        print("testing ....1")
        f = Fernet2(secret.encode("ascii"), backend=backend)
        current_time = calendar.timegm(iso8601.parse_date(now).utctimetuple())
        monkeypatch.setattr(time, "time", lambda: current_time)
        payload = f.decrypt(token.encode("ascii"), ttl=ttl_sec)
        assert payload == src.encode("ascii")

    @json_parametrize(("secret", "token", "now", "ttl_sec"), "invalid.json")
    def test_invalid(self, secret, token, now, ttl_sec, backend, monkeypatch):
        f = Fernet2(secret.encode("ascii"), backend=backend)
        current_time = calendar.timegm(iso8601.parse_date(now).utctimetuple())
        monkeypatch.setattr(time, "time", lambda: current_time)
        with pytest.raises(InvalidToken):
            f.decrypt(token.encode("ascii"), ttl=ttl_sec)

    def test_invalid_start_byte(self, backend):
        f = Fernet2(base64.urlsafe_b64encode(b"\x00" * 32), backend=backend)
        with pytest.raises(InvalidToken):
            f.decrypt(base64.urlsafe_b64encode(b"\x83"))

    def test_timestamp_too_short(self, backend):
        f = Fernet2(base64.urlsafe_b64encode(b"\x00" * 32), backend=backend)
        with pytest.raises(InvalidToken):
            f.decrypt(base64.urlsafe_b64encode(b"\x80abc"))

    def test_non_base64_token(self, backend):
        f = Fernet2(base64.urlsafe_b64encode(b"\x00" * 32), backend=backend)
        with pytest.raises(InvalidToken):
            f.decrypt(b"\x00")

    def test_unicode(self, backend):
        f = Fernet2(base64.urlsafe_b64encode(b"\x00" * 32), backend=backend)
        with pytest.raises(TypeError):
            f.encrypt(u"")
        with pytest.raises(TypeError):
            f.decrypt(u"")

    def test_timestamp_ignored_no_ttl(self, monkeypatch, backend):
        f = Fernet2(base64.urlsafe_b64encode(b"\x00" * 32), backend=backend)
        pt = b"encrypt me"
        token = f.encrypt(pt)
        ts = "1985-10-26T01:20:01-07:00"
        current_time = calendar.timegm(iso8601.parse_date(ts).utctimetuple())
        monkeypatch.setattr(time, "time", lambda: current_time)
        assert f.decrypt(token, ttl=None) == pt

    @pytest.mark.parametrize("message", [b"", b"Abc!", b"\x00\xFF\x00\x80"])
    def test_roundtrips(self, message, backend):
        f = Fernet2(Fernet2.generate_key(), backend=backend)
        assert f.decrypt(f.encrypt(message)) == message

    def test_bad_key(self, backend):
        with pytest.raises(ValueError):
            Fernet2(base64.urlsafe_b64encode(b"abc"), backend=backend)


@pytest.mark.parametrize("backend", [default_backend()])
@pytest.mark.supported(
    only_if=lambda backend: backend.cipher_supported(
        algorithms.AES("\x00" * 32), modes.CBC("\x00" * 16)
    ),
    skip_message="Does not support AES CBC",
)
class TestFernet2(object):
    """Test the new Fernet2 with this class. Make sure it tests all the
    functionalities offered by *Fernet2*.
    """
    @json_parametrize2(
        ("adata", "secret", "ptxt", "ctxt", "iv"), "verify.json",
    )
    # TODO change to above params
    def test_decrypt(self, adata, secret, ptxt, ctxt, iv, backend,
                    monkeypatch):
        print("testing ....decrpyt")
        f = Fernet2(secret.encode("ascii"), backend=backend)
        payload = f.decrypt(ctxt.encode("ascii"), adata = adata)
        assert payload == ptxt.encode("ascii")

    @json_parametrize2(
        ("adata", "secret", "ptxt", "ctxt", "iv"), "verify.json",
    )
    def test_encrypt(self, adata, secret, ptxt, ctxt, iv, backend,
                    monkeypatch):
        print("testing ....encrypt")
        f = Fernet2(secret.encode("ascii"), backend=backend)
        # is this correct or should I use this? base64.urlsafe_b64encode(os.urandom(32))
        current_rand =  os.urandom(16)
        monkeypatch.setattr(os, "urandom", lambda: current_rand)
        # would this even work to check decryption with another key?
        payload = f.decrypt(ctxt.encode("ascii"), adata = adata)
        assert payload == ptxt.encode("ascii")

        # I dont get the difference between test invalid and test verify,
        # do we need a test invalid and test verify for Fernet2?

    def test_adata(self, backend):
        adata = "Hello"
        ptxt = "spring break is coming"
        secret = "cx_0x689RpI-jtRR7oE8h_eQsKImvJapLeSbXpwF4e4="
        f = Fernet2(secret.encode("ascii"), backend=backend)
        ctxt = f.encrypt(ptxt, adata)
        adata_diff = "Hello World"
        with pytest.raises(InvalidToken):
            f.decrypt(token = ctxt, adata = adata_diff)

    # secret = "cx_0x689RpI-jtRR7oE8h_eQsKImvJapLeSbXpwF4e4="
    # # f = Fernet2(base64.urlsafe_b64encode(b"\x00" * 32), backend=default_backend())
    # f = Fernet2(secret, backend=default_backend())
    # msg = "Test Message 2"
    # adata = "Hello"
    # tk = f.encrypt(msg, adata)
    # print("ctxt", tk)
    # txt = f.decrypt(token=tk, adata=adata)
    # print("ptxt", txt)

    # pass
    # check the mac if it authenticates correctly or not
    # keep chaning associated data

class TestPwFernet2(object):
    """
    This is to test the PwFernet class.
    """
    #Test encrypt and test decrypt are both used already 
    # for the lower lever Testfernet2 so they shouldn't be included here? 

    # generate 1000 same cipher test with same password
    # check tfor duplicates 

    # use the same password to encrypt and make sure nothing is repeated
    password = "password"
    f = PWFernet(password, backend=default_backend())
    ptxt = "Crypto"
    s = Set()
    limit = 500
    for i in range(limit):
        ctxt = f.encrypt(ptxt, adata = "Spring break!")
        s.add(ctxt)
    assert len(s) == limit # checking the uniqueness of all the cipher text generated



# t = TestFernet()
# t.test_verify()
# TestFernet2()
# t.test_roundtrips("hello", default_backend())
# TestFernet2()