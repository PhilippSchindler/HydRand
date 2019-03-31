import pytest
import sympy

from hydrand.ed25519 import *
from hydrand.ed25519 import GROUP_ORDER

sample_scalars = [
    0,
    1,
    2,
    3,
    1000,
    2000,
    3000,
    0x09DBC449FD3F23413B9A8461A377D6C56089A50DAC5163C0278767A959F61A78,
    0x0CA9E29061B6C7503C2B1701DC4D22817D180E347F474E08E47764CEE4D248BE,
    0x08ED51B686DD267EED57D6326B4C4E81AAB95EAC387E5C0E4BD2854A35AA79CF,
    GROUP_ORDER - 3,
    GROUP_ORDER - 2,
    GROUP_ORDER - 1,
]

sample_pairs = list(zip(sample_scalars, sample_scalars))


def test_create():
    Scalar(GROUP_ORDER - 1)
    Scalar(0)
    Scalar(4711)


def test_create_random_scalar():
    Scalar.random()


def test_int_conversion():
    assert int(Scalar(GROUP_ORDER - 1)) == GROUP_ORDER - 1
    assert int(Scalar(0)) == 0
    assert int(Scalar(4711)) == 4711


def test_create_random_range():
    assert 0 <= int(Scalar.random()) < GROUP_ORDER


def test_create_negative_scalar():
    with pytest.raises(Exception):
        Scalar(-1)


def test_create_out_of_range_scalar():
    with pytest.raises(ValueError):
        Scalar(GROUP_ORDER)


def test_create_from_bytes_correct_byte_order():
    Scalar.from_bytes(b"\x00" * 32)
    Scalar.from_bytes((GROUP_ORDER - 1).to_bytes(32, BYTE_ORDER))


def test_create_from_bytes_little_endian():
    Scalar.from_bytes(b"\x00" * 32)
    Scalar.from_bytes((GROUP_ORDER - 1).to_bytes(32, "little"))


def test_create_from_bytes_big_endian():
    with pytest.raises(ValueError):
        Scalar.from_bytes((GROUP_ORDER - 1).to_bytes(32, "big"))


def test_create_from_invalid_bytes_length():
    with pytest.raises(ValueError):
        Scalar.from_bytes(b"12")


def test_create_from_invalid_bytes_range():
    with pytest.raises(ValueError):
        Scalar.from_bytes(b"\xff" * 32)


@pytest.mark.parametrize("x, y", sample_pairs)
def test_add(x, y):
    assert int(Scalar(x) + Scalar(y)) == (x + y) % GROUP_ORDER


@pytest.mark.parametrize("x, y", sample_pairs)
def test_sub(x, y):
    assert int(Scalar(x) - Scalar(y)) == (x - y) % GROUP_ORDER


@pytest.mark.parametrize("x, y", sample_pairs)
def test_mul(x, y):
    assert int(Scalar(x) * Scalar(y)) == (x * y) % GROUP_ORDER


@pytest.mark.parametrize("x, y", sample_pairs)
def test_iadd(x, y):
    xs, ys = Scalar(x), Scalar(y)
    x += y
    xs += ys
    x %= GROUP_ORDER
    assert int(xs) == x
    assert int(ys) == y


@pytest.mark.parametrize("x, y", sample_pairs)
def test_isub(x, y):
    xs, ys = Scalar(x), Scalar(y)
    x -= y
    xs -= ys
    x %= GROUP_ORDER
    assert int(xs) == x
    assert int(ys) == y


@pytest.mark.parametrize("x, y", sample_pairs)
def test_imul(x, y):
    xs, ys = Scalar(x), Scalar(y)
    x *= y
    xs *= ys
    x %= GROUP_ORDER
    assert int(xs) == x
    assert int(ys) == y


@pytest.mark.parametrize("x", sample_scalars)
def test_negate(x):
    xs = Scalar(x)
    assert int(-xs) == (-x % GROUP_ORDER)


@pytest.mark.parametrize("x", sample_scalars)
def test_negate_inplace(x):
    xs = Scalar(x)
    xs.negate()
    assert int(xs) == (-x % GROUP_ORDER)


@pytest.mark.parametrize("x", [x for x in sample_scalars if x != 0])
def test_inverse(x):
    xs = Scalar(x)
    assert int(xs.inverse()) == sympy.mod_inverse(x, GROUP_ORDER)


@pytest.mark.parametrize("x", [x for x in sample_scalars if x != 0])
def test_invert(x):
    xs = Scalar(x)
    xs.invert()
    assert int(xs) == sympy.mod_inverse(x, GROUP_ORDER)


@pytest.mark.parametrize("x, y", zip(sample_scalars, [y for y in sample_scalars if y != 0]))
def test_div(x, y):
    assert int(Scalar(x) / Scalar(y)) == (x * sympy.mod_inverse(y, GROUP_ORDER)) % GROUP_ORDER


@pytest.mark.parametrize("x, y", zip(sample_scalars, [y for y in sample_scalars if y != 0]))
def test_idiv(x, y):
    xs, ys = Scalar(x), Scalar(y)
    x = x * sympy.mod_inverse(y, GROUP_ORDER)
    xs /= ys
    x %= GROUP_ORDER
    assert int(xs) == x
    assert int(ys) == y


@pytest.mark.parametrize("x, y", zip(sample_scalars, [y for y in sample_scalars if y != 0]))
def test_pow(x, y):
    assert int(Scalar(x) ** Scalar(y)) == pow(x, y, GROUP_ORDER)


@pytest.mark.parametrize("x, y", zip(sample_scalars, [y for y in sample_scalars if y != 0]))
def test_ipow(x, y):
    xs, ys = Scalar(x), Scalar(y)
    xs **= ys
    assert int(xs) == pow(x, y, GROUP_ORDER)
    assert int(ys) == y


def test_inverse_does_not_exists():
    with pytest.raises(ValueError):
        Scalar(0).inverse()


def test_invert_does_not_exists():
    with pytest.raises(ValueError):
        Scalar(0).invert()


@pytest.mark.parametrize("x, y", sample_pairs)
def test_eq(x, y):
    assert (x == y) == (Scalar(x) == Scalar(y))


@pytest.mark.parametrize("x, y", sample_pairs)
def test_ne(x, y):
    assert (x != y) == (Scalar(x) != Scalar(y))
