import pytest

import hashlib
from copy import copy

from hydrand.ed25519 import fe, Point, Scalar

B = Point.B


def test_base_multiply_by_one():
    assert B == Point.base_times(Scalar(1))


def test_multiply_by_zero_fails():
    with pytest.raises(ValueError):
        B * Scalar(0)


def test_base_times_zero_fails():
    with pytest.raises(ValueError):
        Point.base_times(Scalar(0))


def test_double_eq_times_2():
    assert B + B == B * Scalar(2)


def test_double_inplace():
    B2 = copy(B)
    B2 += B2
    assert B2 == B * Scalar(2)


def test_minus():
    assert (B + B) - B == B


def test_minus_inplace():
    X = B + B
    X -= B
    assert X == B


def test_multiply_inplace():
    X = copy(B)
    X *= Scalar(3)
    assert X == B + B + B


def test_multipy_flipped_order():
    assert B * Scalar(17) == Scalar(17) * B


def test_neg_base_point():
    Bneg = Point(fe.recover_x(B.y, sign=1), B.y)
    assert Bneg != B
    assert Bneg.x != B.x
    assert Bneg.y == B.y
    assert Bneg.sign != B.sign


def test_from_uniform():
    digest = hashlib.sha256(b"some stuff").digest()
    p = Point.from_uniform(digest)
    assert p.is_valid()
