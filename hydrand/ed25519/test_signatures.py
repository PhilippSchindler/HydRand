import os
import sys
import pytest

from hydrand import ed25519
from hydrand.ed25519.testvectors import TEST_VECTORS, TestVector

path = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.append(path)
import ed25519_ref


@pytest.mark.parametrize("v", TEST_VECTORS)
def test_raw(v: TestVector):
    assert len(v.seed) == 32
    assert len(v.public_key) == 32
    assert len(v.signature) == 64

    sk, pk, _ = ed25519._loadkey(v.seed)
    sig = ed25519._sign(v.seed, v.message)
    sigbytes = bytes(sig[0]) + bytes(sig[1])

    assert bytes(pk) == v.public_key
    assert sigbytes == v.signature


@pytest.mark.parametrize("v", TEST_VECTORS)
def test_with_libsodium(v: TestVector):
    assert len(v.seed) == 32
    assert len(v.public_key) == 32
    assert len(v.signature) == 64

    keypair = ed25519.KeyPair(v.seed)
    sig = ed25519.sign_detached(v.message, keypair.secret_key)

    assert bytes(keypair.public_key) == v.public_key
    assert sig == v.signature
