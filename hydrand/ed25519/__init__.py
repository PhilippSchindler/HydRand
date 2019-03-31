from typing import ByteString, Any

import ctypes
import os
import secrets
import hashlib

from . import fe


# path to the share library file libsodium
# we require a custom version which also exports the function crypto_core_ed25519_scalar_mul
LIBSODIUM_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "lib", "custom-libsodium.so"))

BYTE_ORDER = "little"
FIELD_MODULUS = 2 ** 255 - 19
GROUP_ORDER = 2 ** 252 + 27742317777372353535851937790883648493

c_bytes32 = ctypes.ARRAY(ctypes.c_char, 32)  # type: ignore
c_bytes64 = ctypes.ARRAY(ctypes.c_char, 64)  # type: ignore


def load_libsodium():
    lib = ctypes.cdll.LoadLibrary(LIBSODIUM_PATH)
    if not lib:
        raise ImportError(f"Unable to import libsodium from {LIBSODIUM_PATH}")

    def version_check(required_version):
        def astuple(version_str):
            return tuple(map(int, version_str.split(".")))

        lib.sodium_version_string.restype = ctypes.c_char_p
        sodium_version = lib.sodium_version_string().decode()
        ok = astuple(sodium_version) >= astuple(required_version)
        assert ok, f"Invalid libsodium version {sodium_version}, version {required_version} or newer is required!"

    version_check("1.0.17")
    return lib


lib = load_libsodium()


def _get_read_buffer_ptr(value: ByteString, offset=0) -> ctypes.c_void_p:
    pyobj = ctypes.py_object(value)
    ptr = ctypes.c_void_p()
    buf_length = ctypes.c_size_t()
    ctypes.pythonapi.PyObject_AsReadBuffer(pyobj, ctypes.byref(ptr), ctypes.byref(buf_length))
    if offset:
        return ctypes.c_void_p(ptr.value + offset)
    return ptr


def _get_write_buffer_ptr(value: ByteString, offset=0) -> ctypes.c_void_p:
    pyobj = ctypes.py_object(value)
    ptr = ctypes.c_void_p()
    buf_length = ctypes.c_size_t()
    ctypes.pythonapi.PyObject_AsWriteBuffer(pyobj, ctypes.byref(ptr), ctypes.byref(buf_length))
    if offset:
        return ctypes.c_void_p(ptr.value + offset)
    return ptr


class Point:
    """ class representing a group element, wraps to the underlying implementation in C """

    __slots__ = ["value", "_ptr"]

    B: "Point"
    ONE: "Point"

    value: ByteString
    _ptr: ctypes.c_void_p

    def __new__(self, x: int, y: int):
        if not isinstance(x, int) or not isinstance(y, int):
            raise TypeError()
        if not (0 <= x < FIELD_MODULUS) or not (0 <= y < FIELD_MODULUS):
            raise ValueError()

        y_packed = y | ((x & 1) << 255)
        point = Point.from_bytes(y_packed.to_bytes(32, BYTE_ORDER))

        if (point.x, point.y) != (x, y):
            raise ValueError("The given data represents an invalid point!")

        return point

    @staticmethod
    def _create_raw(value: ByteString = None, readonly=True):
        point = object.__new__(Point)
        if value:
            point.value = value
            if readonly:
                point._ptr = _get_read_buffer_ptr(point.value)
            else:
                point._ptr = _get_write_buffer_ptr(point.value)
        else:
            point.value = bytearray(32)
            point._ptr = _get_write_buffer_ptr(point.value)
        return point

    @staticmethod
    def from_bytes(value: ByteString):
        if len(value) != 32:
            raise ValueError("Invalid data format (32 bytes expected)!")

        ptr = _get_read_buffer_ptr(value)
        point = Point._create_raw(value, ptr)

        if not point.is_valid():
            raise ValueError("The given data represents an invalid point!")
        return point

    @staticmethod
    def from_uniform(data: bytes) -> "Point":
        if len(data) == 32:
            input_ptr = _get_read_buffer_ptr(data)
            result = Point._create_raw()
            if lib.crypto_core_ed25519_from_uniform(result._ptr, input_ptr) == 0:
                return result
            assert False, "Some internal error, should not happen!"
        raise ValueError("Invalid data format (32 bytes expected)!")

    @staticmethod
    def base_times(scalar: "Scalar") -> "Point":
        if isinstance(scalar, Scalar):
            result = Point._create_raw()
            if lib.crypto_scalarmult_ed25519_base_noclamp(result._ptr, scalar._ptr) == 0:
                return result
            raise ValueError("Scalar/Point multiplication failed!")
        raise TypeError()

    @property
    def x(self):
        return fe.recover_x(self.y, self.sign)

    @property
    def y(self):
        y_and_sign = int.from_bytes(self.value, BYTE_ORDER)
        return y_and_sign & ((1 << 255) - 1)

    @property
    def sign(self):
        return self.value[-1] >> 7

    def is_valid(self) -> bool:
        return bool(lib.crypto_core_ed25519_is_valid_point(self._ptr))

    def __eq__(self, other):
        if isinstance(other, Point):
            if self is other:
                return True
            return lib.sodium_memcmp(self._ptr, other._ptr, 32) == 0
        return False

    def __ne__(self, other):
        if isinstance(other, Point):
            if self is other:
                return False
            return lib.sodium_memcmp(self._ptr, other._ptr, 32) != 0
        return True

    def __add__(self, other: "Point") -> "Point":
        if isinstance(other, Point):
            result = Point._create_raw()
            if lib.crypto_core_ed25519_add(result._ptr, self._ptr, other._ptr) == 0:
                return result
            raise ValueError("Point addition failed!")
        raise TypeError()

    def __sub__(self, other: "Point") -> "Point":
        if isinstance(other, Point):
            result = Point._create_raw()
            if lib.crypto_core_ed25519_sub(result._ptr, self._ptr, other._ptr) == 0:
                return result
            raise ValueError("Point substraction failed!")
        raise TypeError()

    def __mul__(self, other: "Scalar") -> "Point":
        if self is Point.B:
            return Point.base_times(other)
        if isinstance(other, Scalar):
            result = Point._create_raw()
            if lib.crypto_scalarmult_ed25519_noclamp(result._ptr, other._ptr, self._ptr) == 0:
                return result
            raise ValueError("Scalar/Point multiplication failed!")
        raise TypeError()

    def __bytes__(self) -> bytes:
        return bytes(self.value)

    def __copy__(self):
        return Point._create_raw(bytearray(self.value))

    def __len__(self) -> int:
        return 32

    def __repr__(self):
        if self.is_valid():
            return f"Point(0x{self.x:064x}, \n      0x{self.y:064x})"
        return f"Point(INVALID, y=0x{self.y:064x})"


Point.B = Point(*fe.B)
Point.ONE = Point._create_raw(b"\x01" + b"\x00" * 31)


class Scalar:

    __slots__ = ["value", "_ptr"]

    value: ByteString
    _ptr: ctypes.c_void_p

    def __new__(cls, scalar: int):
        if isinstance(scalar, int):
            return Scalar.from_bytes(scalar.to_bytes(32, BYTE_ORDER))
        else:
            raise TypeError()

    @staticmethod
    def from_bytes(data: bytes) -> "Scalar":
        if len(data) == 32:
            scalar = Scalar._create_raw(data)
            if scalar.is_valid():
                return scalar
            raise ValueError("The given scalar is not in the expected range!")
        raise ValueError("Invalid data format (32 bytes expected)!")

    @staticmethod
    def reduce(data: bytes) -> "Scalar":
        """ obtain a uniformly distributed scalar value from a at least 40 bytes (~317 bit) random data,
            typically the output of a cryptographic hashfunction
        """
        if isinstance(data, bytes) and len(data) >= 40:
            scalar = Scalar._create_raw()
            input_ptr = _get_read_buffer_ptr(data)
            lib.crypto_core_ed25519_scalar_reduce(scalar._ptr, input_ptr)
            return scalar

        raise ValueError("Invalid data format (>= 40 bytes expected)!")

    @staticmethod
    def _create_raw(value: ByteString = None, readonly=True):
        scalar = object.__new__(Scalar)
        if value:
            scalar.value = value
            if readonly:
                scalar._ptr = _get_read_buffer_ptr(scalar.value)
            else:
                scalar._ptr = _get_write_buffer_ptr(scalar.value)
        else:
            scalar.value = bytearray(32)
            scalar._ptr = _get_write_buffer_ptr(scalar.value)
        return scalar

    def is_valid(self) -> bool:
        """ see: int sc25519_is_canonical(const unsigned char s[32]));
            checks if 0 <= self < CURVE_ORDER holds
        """
        val = int(self)
        return 0 <= val < GROUP_ORDER

    @staticmethod
    def random() -> "Scalar":
        return Scalar(secrets.randbelow(GROUP_ORDER))

    def __eq__(self, other):
        if isinstance(other, Scalar):
            if self is other:
                return True
            return lib.sodium_memcmp(self._ptr, other._ptr, 32) == 0
        return False

    def __ne__(self, other):
        if isinstance(other, Scalar):
            if self is other:
                return False
            return lib.sodium_memcmp(self._ptr, other._ptr, 32) != 0
        return True

    def __add__(self, other: "Scalar") -> "Scalar":
        if isinstance(other, Scalar):
            result = Scalar._create_raw()
            lib.crypto_core_ed25519_scalar_add(result._ptr, self._ptr, other._ptr)
            return result
        raise TypeError()

    def __sub__(self, other: "Scalar") -> "Scalar":
        if isinstance(other, Scalar):
            result = Scalar._create_raw()
            lib.crypto_core_ed25519_scalar_sub(result._ptr, self._ptr, other._ptr)
            return result
        raise TypeError()

    def __mul__(self, other):
        if isinstance(other, Scalar):
            result = Scalar._create_raw()
            lib.crypto_core_ed25519_scalar_mul(result._ptr, self._ptr, other._ptr)
            return result
        if isinstance(other, Point):
            return other * self
        raise TypeError()

    def __truediv__(self, other: "Scalar") -> "Scalar":
        if isinstance(other, Scalar):
            return self * other.inverse()
        raise TypeError()

    def __neg__(self):
        """ compute the negation of the current scalar as new scalar
            s + neg = 0 (mod CURVE_ORDER)
        """
        result = Scalar._create_raw()
        lib.crypto_core_ed25519_scalar_negate(result._ptr, self._ptr)
        return result

    def __pow__(self, other):
        """ using python's internal pow function as the libary does not provide a pow
            might be somewhat slow
        """
        v = pow(int(self), int(other), GROUP_ORDER)
        return Scalar._create_raw(v.to_bytes(32, BYTE_ORDER))

    def negate(self):
        """ compute the negation of the current scalar inplace
            s + neg = 0 (mod CURVE_ORDER)
        """
        lib.crypto_core_ed25519_scalar_negate(self._ptr, self._ptr)
        return self

    def inverse(self):
        """ return a new Scalar with is the multiplicate inverse of the current one
        """
        result = Scalar._create_raw()
        if lib.crypto_core_ed25519_scalar_invert(result._ptr, self._ptr) == 0:
            return result
        else:
            raise ValueError("Inverse does not exist")

    def invert(self):
        """ compute the multiplicate inverse of the current scalar inplace
        """
        if lib.crypto_core_ed25519_scalar_invert(self._ptr, self._ptr) == 0:
            return self
        else:
            raise ValueError("Inverse does not exist")

    def __bytes__(self) -> bytes:
        return bytes(self.value)

    def __int__(self) -> int:
        return int.from_bytes(self.value, BYTE_ORDER)

    def __len__(self) -> int:
        return 32

    def __copy__(self):
        return Scalar._create_raw(bytearray(self.value))

    def __repr__(self):
        return f"Scalar(0x{int(self):064x})"


class SecretKey:

    __slots__ = ["value", "_ptr"]

    value: Any
    _ptr: Any

    def __init__(self):
        assert False, "Always initialize using the Keypair class!"

    def __bytes__(self) -> bytes:
        return bytes(self.value)


def H(message: bytes):
    h = hashlib.sha512(message).digest()
    hint = int.from_bytes(h, BYTE_ORDER) % GROUP_ORDER
    return Scalar(hint)


def _loadkey(secret_key_seed: bytes):
    if not isinstance(secret_key_seed, bytes):
        raise TypeError()
    if len(secret_key_seed) != 32:
        raise ValueError()

    hashed_seed = hashlib.sha512(secret_key_seed).digest()
    a = int.from_bytes(hashed_seed[:32], BYTE_ORDER)
    r_seed = hashed_seed[32:]
    a &= (1 << 254) - 8
    a |= 1 << 254

    secret_key = Scalar(a % GROUP_ORDER)
    public_key = Point.base_times(secret_key)

    return secret_key, public_key, r_seed


def _sign(secret_key_seed: bytes, message: bytes):
    if not isinstance(message, bytes):
        raise TypeError()

    secret_key, public_key, r_seed = _loadkey(secret_key_seed)

    r = H(r_seed + message)
    R = Point.base_times(r)
    h = H(bytes(R) + bytes(public_key) + message)
    s = r + (h * secret_key)
    return R, s


class KeyPair:

    # The seed is used a root value to derive all other values.
    # Must be keept secret!
    seed: bytes

    # Notice that this is the actual private scalar value used to derive the Point representing the public key.
    # This value is different from the notion of a secret key in libsodiums terminology.
    # It is used mostly by the PVSS algorithms.
    secret_scalar: Scalar

    # This is what libsodium consider to be a secret key used to signing messages.
    # I.e. a 64 bytes vector concatinated of the seed (32 bytes) and the public! key (32 bytes).
    # This might be somewhat confusing! See e.g. https://blog.mozilla.org/warner/2011/11/29/ed25519-keys/ for an
    # in depth explaination on how keys are derived.
    secret_key: SecretKey

    # Point object representating a public key.
    # This value is equivalent to what libsodium considers to be a public key.
    # Also used in the PVSS algorithms.
    public_key: Point

    def __init__(self, seed: bytes):
        if seed is None or len(seed) != 32:
            raise ValueError()

        self.public_key = Point._create_raw()
        self.secret_key = SecretKey.__new__(SecretKey)

        self.secret_key.value = bytearray(64)
        self.secret_key._ptr = _get_write_buffer_ptr(self.secret_key.value)

        seed_ptr = _get_read_buffer_ptr(seed)

        assert lib.crypto_sign_seed_keypair(self.public_key._ptr, self.secret_key._ptr, seed_ptr) == 0
        self.seed = bytes(self.secret_key.value[:32])

        h = hashlib.sha512(self.seed).digest()
        s = int.from_bytes(h[:32], BYTE_ORDER)
        s &= (1 << 254) - 8
        s |= 1 << 254
        self.secret_scalar = Scalar(s % GROUP_ORDER)

    def __eq__(self, other):
        if isinstance(other, KeyPair):
            return self.seed == other.seed

    @staticmethod
    def random() -> "KeyPair":
        return KeyPair(secrets.token_bytes(32))


def sign_detached(message: ByteString, secret_key: SecretKey) -> bytearray:
    msg_ptr = _get_read_buffer_ptr(message)
    sig = bytearray(64)
    sig_ptr = _get_write_buffer_ptr(sig)
    sig_len = ctypes.c_longlong()
    assert lib.crypto_sign_detached(sig_ptr, ctypes.byref(sig_len), msg_ptr, len(message), secret_key._ptr) == 0
    return sig


# def append_signature(buffer: bytearray, offset: int, msglen: int, secret_key: SecretKey):
#     cmsg = ctypes.ARRAY(ctypes.c_char, msglen).from_buffer(buffer, offset)  # type: ignore
#     csig = ctypes.ARRAY(ctypes.c_char, 64).from_buffer(buffer, offset + msglen)  # type: ignore
#     csiglen = ctypes.c_longlong()
#     assert lib.crypto_sign_detached(csig, ctypes.byref(csiglen), cmsg, msglen, secret_key._ptr) == 0


def verify_detached(message: ByteString, signature: ByteString, public_key: Point) -> bool:
    msg_ptr = _get_read_buffer_ptr(message)
    sig_ptr = _get_read_buffer_ptr(signature)
    return lib.crypto_sign_verify_detached(sig_ptr, msg_ptr, len(message), public_key._ptr) == 0


def verify_attached(signed_message: ByteString, public_key: Point) -> bool:
    msg_len = len(signed_message) - 64
    msg_ptr = _get_read_buffer_ptr(signed_message)
    sig_ptr = _get_read_buffer_ptr(signed_message, offset=msg_len)
    return lib.crypto_sign_verify_detached(sig_ptr, msg_ptr, msg_len, public_key._ptr) == 0
