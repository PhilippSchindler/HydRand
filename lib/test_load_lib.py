import os
import ctypes


def test_load_lib():
    libpath = os.path.join(os.path.dirname(__file__), "./custom-libsodium.so")
    lib = ctypes.cdll.LoadLibrary(os.path.join(libpath))

    def random_scalar(result=None):
        if not result:
            result = ctypes.create_string_buffer(32)
        lib.crypto_core_ed25519_scalar_random(result)
        return result

    r = ctypes.create_string_buffer(32)
    a = random_scalar()
    b = random_scalar()

    lib.crypto_core_ed25519_scalar_mul(r, a, b)

    ai = int.from_bytes(a.raw, "little")
    bi = int.from_bytes(b.raw, "little")
    ri = int.from_bytes(r.raw, "little")

    assert ri == (ai * bi) % (2 ** 252 + 27742317777372353535851937790883648493)
