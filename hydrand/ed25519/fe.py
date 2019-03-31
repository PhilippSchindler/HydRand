# somewhat slow functions for computations mod 2**255 + 19
# used for testing and debuging

# heavily based on ed25519_ref

# field modulus
p = 2 ** 255 - 19

# group order
q = 2 ** 252 + 27742317777372353535851937790883648493


def add(x, y):
    return (x + y) % p


def sub(x, y):
    return (x - y) % p


def mul(x, y):
    return (x * y) % p


def mod_inv(x):
    return pow(x, p - 2, p)


def div(x, y):
    return mul(x, mod_inv(y))


# curve constant
d = mul(-121665, mod_inv(121666))

# sqrt of -1 % p
mod_sqrt_m1 = pow(2, (p - 1) // 4, p)


def recover_x(y, sign):
    if y >= p:
        raise ValueError("Given arguments do not represent a valid point!")
    x2 = (y * y - 1) * mod_inv(d * y * y + 1)
    if x2 == 0:
        if sign:
            raise ValueError("Given arguments do not represent a valid point!")
        else:
            return 0

    # Compute square root of x2
    x = pow(x2, (p + 3) // 8, p)
    if (x * x - x2) % p != 0:
        x = x * mod_sqrt_m1 % p
    if (x * x - x2) % p != 0:
        return None

    if (x & 1) != sign:
        x = p - x
    return x


B = (
    15112221349535400772501151409588531511454012693041857206046113283949847762202,
    46316835694926478169428394003475163141307993866256225615783033603165251855960,
)

assert B == (recover_x(div(4, 5), 0), div(4, 5))
