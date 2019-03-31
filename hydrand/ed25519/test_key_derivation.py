import ctypes
import hashlib

from hydrand.ed25519 import *


def test_key_derivation():

    assert lib.crypto_sign_seedbytes() == 32
    assert lib.crypto_sign_secretkeybytes() == 64
    assert lib.crypto_sign_publickeybytes() == 32

    seed = (
        b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
        b"\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"
    )

    kp = KeyPair(seed)

    assert kp.seed == seed
    assert kp.public_key == Point.base_times(kp.secret_scalar)
