import hashlib

from typing import Optional

from hydrand.ed25519 import KeyPair, Scalar


def deterministic_random_bytes(num_bytes: int, purpose: Optional[str] = None, counter: Optional[int] = None) -> bytes:
    if purpose is None:
        purpose = "__undefined_purpose__"

    if counter is None:
        val = purpose.encode()
    else:
        val = purpose.encode() + b" || " + str(counter).encode()

    return hashlib.shake_256(val).digest(num_bytes)


def deterministic_random_scalar(purpose: Optional[str] = None, counter: Optional[int] = None):
    purpose = "__scalar__ || " + (purpose or "")
    return Scalar.reduce(deterministic_random_bytes(64, purpose, counter))


def determinisitic_random_keypair(node_id: int) -> KeyPair:
    return KeyPair(deterministic_random_bytes(32, "__key_pair_seed__", node_id))
