""" implementation of the publicly-verifiable secret sharing protocol described in Scrape
    we use the DDH variant from page 12 of the Scrape paper
    see: https://eprint.iacr.org/2017/216.pdf
"""

import hashlib
from copy import copy
from typing import List, Optional, Tuple

from hydrand.data import ShareCorrectnessProof, ShareDecryptionProof
from hydrand.ed25519 import Point, Scalar, GROUP_ORDER

# initialize two independent generator points g, and h
G = Point.from_uniform(hashlib.sha256(bytes(Point.B)).digest())
H = Point.B


class Polynomial:
    def __init__(self, coeffs: List[Scalar]):
        self.coeffs = coeffs

    def __call__(self, arg: int) -> Scalar:
        x = Scalar(arg)
        result = self.coeffs[0] + (self.coeffs[1] * x)
        x_pow = copy(x)
        for i in range(2, len(self.coeffs)):
            x_pow *= x
            result += self.coeffs[i] * x_pow
        return result

    @staticmethod
    def random(degree: int, secret: Optional[Scalar] = None) -> "Polynomial":
        """ Return a polynomial with random coefficients from Zq.
            p(x) = c_0 + c_1*x + ... c_{degree} * x^{degree}
        """
        if secret is None:
            coeffs = [Scalar.random() for i in range(degree + 1)]
        else:
            coeffs = [secret] + [Scalar.random() for i in range(degree)]
        return Polynomial(coeffs)

    # @staticmethod
    # def from_seed(degree: int, seed: bytes) -> "Polynomial":
    #     """ Uses a cryptographic random number generator to obtain the coefficients of the polynom.
    #          This function is deterministic, it used a 256 bit scalar as seed.
    #     """
    #     if seed is None or len(seed) != 32:
    #         raise ValueError("Invalid seed: seed must be 32 bytes.")

    #     c_seed = ctypes.create_string_buffer(seed, 32)
    #     buffer_size = 64 * (degree + 1)
    #     buffer = ctypes.create_string_buffer(buffer_size)
    #     buffer_ptr = ctypes.cast(buffer, ctypes.c_void_p)
    #     lib.randombytes_buf_deterministic(buffer, buffer_size, c_seed)

    #     coeffs = [create_scalar() for _ in range(degree + 1)]
    #     for c in coeffs:
    #         lib.crypto_core_ed25519_scalar_reduce(c._c, buffer_ptr)
    #         buffer_ptr.value += 64  # type: ignore

    #     return Polynomial(coeffs)


def keygen():
    """ generates a fresh ed25519 keypair (sk, pk = h^sk) for a participant in the PVSS
    """
    secret_key = Scalar.random()
    public_key = H * secret_key
    return secret_key, public_key


def share_random_secret(
    receiver_public_keys: List[Point], recovery_threshold: int, secret_scalar: Optional[Scalar] = None
) -> Tuple[Scalar, List[Point], ShareCorrectnessProof]:
    """ generate a fresh random base secret s (or uses the provided one)
        computes share (s_1, ..., s_n) for S = h^s
        encrypts them with the public keys to obtain ŝ_1, ..., ŝ_n
        compute the verification information
        returns
         - the secret s (which can is used to reveal and verify S)
         - the encrypted shares ŝ_1, ..., ŝ_n
         - the share verification information, i.e. PROOF_D, which consists of
            - the commitments v_1, ..., v_n   (v_i = g^{s_i})
            - the (common) challenge e
            - the responses z_1, ..., z_n
    """
    num_receivers = len(receiver_public_keys)

    secret = secret_scalar or Scalar.random()
    poly = Polynomial.random(recovery_threshold - 1, secret)

    shares = [poly(i) for i in range(1, num_receivers + 1)]
    encrypted_shares = [pk * share for pk, share in zip(receiver_public_keys, shares)]
    proof = prove_share_correctness(shares, encrypted_shares, receiver_public_keys)

    return secret, encrypted_shares, proof


def decrypt_share(share, secret_key):
    return share * secret_key.inverse()


def _listify(*values_or_lists):
    """ helper function which turns each argument into a single element list if it is not already a list
        used for a consise implementation of _DLEQ_prove and _DLEQ_verify
    """
    return [v if isinstance(v, list) else [v] for v in values_or_lists]


def _DLEQ_prove(g, x, h, y, α):
    """ Performs a the DLEQ NIZK protocol for the given values g, x, h, y and the exponent α.
        I.e. the prover shows that he knows α such that x = g^α and y = h^α holds.
        To perform the proving prodedure in parallel (but with a common challenge) g, x, h, y and α might be lists.
    """
    g, x, h, y, α = _listify(g, x, h, y, α)
    assert len(g) == len(x) == len(h) == len(y) == len(α)
    n = len(g)

    w = [Scalar.random() for _ in range(n)]  # w random element from Zq
    a1 = [g[i] * w[i] for i in range(n)]  # a1 = g^w
    a2 = [h[i] * w[i] for i in range(n)]  # a2 = h^w
    e = _DLEQ_derive_challenge(x, y, a1, a2)  # the challenge e
    z = [w[i] - (α[i] * e) for i in range(n)]  # the response(s) z
    return e, z[0] if n == 1 else z


def _DLEQ_verify(g, x, h, y, e, z):
    """ Performs a the verification procedure of DLEQ NIZK protocol for the given values g, x, h, y
        the (common) challenge e and the response(s) z.
        To perform the verification in parallel (with a common challenge e) g, x, h, y and z might be lists.
    """
    g, x, h, y, z = _listify(g, x, h, y, z)
    assert len(g) == len(x) == len(h) == len(y) == len(z)
    n = len(g)

    a1 = [(g[i] * z[i]) + (x[i] * e) for i in range(n)]  # a1 = g^z * x^e
    a2 = [(h[i] * z[i]) + (y[i] * e) for i in range(n)]  # a2 = h^z * y^e

    e_computed = _DLEQ_derive_challenge(x, y, a1, a2)
    return e == e_computed


def _DLEQ_derive_challenge(x, y, a1, a2):
    """ Compute (common) challenge e = H(x_1, y_1, a_11, a_21, ..., x_n, y_n, a_1n, a_2n).
        Compared to the SCRAPE paper the order of the arguments is changed for a consise implementation.
    """
    n = len(x)
    hasher = hashlib.sha512()
    for i in range(n):
        hasher.update(bytes(x[i]))
        hasher.update(bytes(y[i]))
        hasher.update(bytes(a1[i]))
        hasher.update(bytes(a2[i]))
    return Scalar.reduce(hasher.digest())


def prove_share_correctness(
    shares: List[Scalar], encrypted_shares: List[Point], public_keys: List[Point]
) -> ShareCorrectnessProof:
    """ Returns commitments to the shares and a NIZK proof (DLEQ) proofing that
        the encrypted_shares are correctly derived.
    """
    # notation used in Scrape paper and analogs here
    # x... commitments
    # y... encrypted shares
    # g... G
    # h... public_keys
    # α... shares
    # e... challenge
    # z... responses

    n = len(shares)
    commitments = [G * share for share in shares]

    assert len(commitments) == n
    assert len(public_keys) == n
    assert len(encrypted_shares) == n
    assert len(shares) == n
    assert len([G] * n) == n

    challenge, responses = _DLEQ_prove([G] * n, commitments, public_keys, encrypted_shares, shares)
    return ShareCorrectnessProof(commitments, challenge, responses)


def verify_shares(
    encrypted_shares: List[Point], proof: ShareCorrectnessProof, public_keys: List[Point], recovery_threshold: int
) -> bool:
    """ Verify that the given encrypted shares are computed accoring to the protocol.
        Returns True if the encrypted shares are valid.
        If this functions returns True, a collaboration of t nodes is able to recover the secret S.
    """
    num_nodes = len(public_keys)
    commitments, challenge, responses = proof.commitments, proof.challenge, proof.responses

    # 1. verify the DLEQ NIZK proof
    if not _DLEQ_verify([G] * num_nodes, commitments, public_keys, encrypted_shares, challenge, responses):
        return False

    # 2. verify the validity of the shares by sampling and testing with a random codeword
    codeword = _random_codeword(num_nodes, recovery_threshold)
    product = commitments[0] * codeword[0]
    for i in range(1, num_nodes):
        product += commitments[i] * codeword[i]
    return product == Point.ONE


def verify_secret(secret: Scalar, commitments: List[Point], recovery_threshold: int) -> bool:
    """ Checks if a revealed secret indeed corresponding to a provided commitment.
        Returns True if the secret is valid.
        Returns False is the secret is invalid.
        Also returns False if the secret is valid but the commitment
        (i.e. the coefficients of the underlying polynomial) where not derive according to the protocol.
    """

    # This verfication procedure is not described in the Scrape paper.
    # We perform the following steps:
    # 1. Obtain v_0 via Langrange interpolation from v_1, ..., v_t, or from any other t-sized subset of {v_1, ..., v_n}.
    #    This is possible as the commitments v_1, ... v_n are all public information after the secret has been shared.
    # 2. Use the fact v_0 = g^p(0) = g^s to verify that the given secret s is valid.

    t_indexed_commitments = [(i, v) for i, v in zip(range(1, recovery_threshold + 1), commitments)]
    v0 = recover(t_indexed_commitments)
    return v0 == G * secret


def prove_share_decryption(decrypted_share, encrypted_share, secret_key, public_key):
    """ Proves that decrypted_share is a valid decryption for the given public key.
        i.e. implements DLEQ(h, pk_i, s~_i, ŝ_i)
    """
    challenge, response = _DLEQ_prove(H, public_key, decrypted_share, encrypted_share, secret_key)
    return ShareDecryptionProof(challenge, response)


def verify_decrypted_share(decrypted_share, encrypted_share, public_key, proof):
    """ Check that the given share does indeed correspond to the given encrypted share.
        Returns True if the share is valid.
    """
    challenge, response = proof.challenge, proof.response
    return _DLEQ_verify(H, public_key, decrypted_share, encrypted_share, challenge, response)


def recover(indexed_shares):
    """ Takes EXACTLY t (idx, decrypted_share) tuples and performs Langrange interpolation to recover the secret S.
        The validity of the decrypted shares has to be verified prior to a call of this function.
    """
    idxs = [Scalar(idx) for idx, _ in indexed_shares]
    idx, share = indexed_shares[0]
    rec = share * _lagrange_coefficient(Scalar(idx), idxs)
    for idx, share in indexed_shares[1:]:
        rec += share * _lagrange_coefficient(Scalar(idx), idxs)
    return rec


def _random_codeword(num_nodes: int, recovery_threshold: int) -> List[Scalar]:
    f = Polynomial.random(num_nodes - recovery_threshold - 1)
    codeword = []
    for i in range(1, num_nodes + 1):
        # vi's could be precomputed given n and t
        vi = Scalar(1)
        for j in range(1, num_nodes + 1):
            if j != i:
                vi *= Scalar((i - j) % GROUP_ORDER)
        vi.invert()
        codeword.append(vi * f(i))
    return codeword


def _lagrange_coefficient(i, idxs):
    numerator = Scalar(1)
    denominator = Scalar(1)
    for j in idxs:
        if j != i:
            numerator *= j
            denominator *= j - i
    return numerator / denominator
