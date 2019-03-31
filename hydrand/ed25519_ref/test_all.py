import os
import sys
import pytest

from hydrand.ed25519_ref import *
from hydrand.ed25519.testvectors import TEST_VECTORS, TestVector


@pytest.mark.parametrize("v", TEST_VECTORS)
def test(v: TestVector):
    assert len(v.seed) == 32
    assert len(v.public_key) == 32
    assert len(v.signature) == 64
    assert point_compress(point_decompress(v.public_key)) == v.public_key
    assert secret_to_public(v.seed) == v.public_key
    assert sign(v.seed, v.message) == v.signature
    assert verify(v.public_key, v.message, v.signature)
    assert not verify(v.public_key, v.message + b"\x00", v.signature)
    assert not verify(v.public_key, v.message, bytes(reversed(v.signature)))

