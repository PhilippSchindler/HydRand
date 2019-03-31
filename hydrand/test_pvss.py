import random

from hydrand.pvss import (
    keygen,
    decrypt_share,
    share_random_secret,
    prove_share_decryption,
    verify_decrypted_share,
    verify_shares,
    verify_secret,
    ShareCorrectnessProof,
    recover,
    Polynomial,
)
from hydrand.pvss import G, H, _DLEQ_prove, _DLEQ_verify
from hydrand.ed25519 import Scalar

NUM_NODES = 10
RECOVERY_THRESHOLD = 5

keypairs = [keygen() for _ in range(NUM_NODES)]
secret_keys = [key[0] for key in keypairs]
public_keys = [key[1] for key in keypairs]
secret, encrypted_shares, proof = share_random_secret(public_keys, RECOVERY_THRESHOLD)
decrypted_shares = [decrypt_share(share, sk) for share, sk in zip(encrypted_shares, secret_keys)]


def test_dleq():
    α = Scalar.random()
    e, z = _DLEQ_prove(G, G * α, H, H * α, α)
    assert _DLEQ_verify(G, G * α, H, H * α, e, z)


def test_dleq_invalid_challenge():
    α = Scalar.random()
    e, z = _DLEQ_prove(G, G * α, H, H * α, α)
    e += Scalar(1)
    assert not _DLEQ_verify(G, G * α, H, H * α, e, z)


def test_dleq_non_equal():
    a = Scalar.random()
    b = Scalar.random()
    e, z = _DLEQ_prove(G, G * a, H, H * b, a)
    assert not _DLEQ_verify(G, G * a, H, H * b, e, z)


def test_dleq_parallel():
    α = [Scalar.random() for _ in range(10)]
    g = [G * Scalar.random() for _ in range(10)]
    x = [g[i] * α[i] for i in range(10)]
    h = [H * Scalar.random() for _ in range(10)]
    y = [h[i] * α[i] for i in range(10)]
    e, z = _DLEQ_prove(g, x, h, y, α)
    assert _DLEQ_verify(g, x, h, y, e, z)


# def test_share_decryption():
#     poly = _derive_polynomial(secret, RECOVERY_THRESHOLD)
#     for i, encrypted_share, secret_key in zip(range(1, NUM_NODES + 1), encrypted_shares, secret_keys):
#         assert H * poly(i) == decrypt_share(encrypted_share, secret_key)


def test_verification_of_decrypted_share():
    for enc_share, sk, pk in zip(encrypted_shares, secret_keys, public_keys):
        dec_share = decrypt_share(enc_share, sk)
        proof = prove_share_decryption(dec_share, enc_share, sk, pk)
        assert verify_decrypted_share(dec_share, enc_share, pk, proof)


def test_share_verification():
    assert verify_shares(encrypted_shares, proof, public_keys, RECOVERY_THRESHOLD)


def test_share_verification_invalid_commitments():
    commitments, challenge, responses = proof.commitments, proof.challenge, proof.responses
    commitments = list(reversed(commitments))
    assert not verify_shares(
        encrypted_shares, ShareCorrectnessProof(commitments, challenge, responses), public_keys, RECOVERY_THRESHOLD
    )


def test_share_verification_invalid_challenge():
    commitments, challenge, responses = proof.commitments, proof.challenge, proof.responses
    challenge = challenge + Scalar(1)
    assert not verify_shares(
        encrypted_shares, ShareCorrectnessProof(commitments, challenge, responses), public_keys, RECOVERY_THRESHOLD
    )


def test_share_verification_invalid_response():
    commitments, challenge, responses = proof.commitments, proof.challenge, proof.responses
    responses = list(reversed(responses))
    assert not verify_shares(
        encrypted_shares, ShareCorrectnessProof(commitments, challenge, responses), public_keys, RECOVERY_THRESHOLD
    )


def test_recover_secret():
    indexed_shares = [(i, share) for i, share in zip(range(1, NUM_NODES + 1), decrypted_shares)]
    selected_shares = random.sample(indexed_shares, RECOVERY_THRESHOLD)
    assert recover(selected_shares) == H * secret


def test_obtain_v0():
    p = Polynomial.random(RECOVERY_THRESHOLD - 1)
    assert len(p.coeffs) == RECOVERY_THRESHOLD

    v0, *commitments = [G * p(i) for i in range(NUM_NODES + 1)]
    indexed_commitments = [(i, v) for i, v in zip(range(1, NUM_NODES + 1), commitments)]
    selected_commitments = random.sample(indexed_commitments, RECOVERY_THRESHOLD)

    v0_comp = recover(selected_commitments)
    assert v0 == v0_comp


def test_verify_secret():
    commitments = proof.commitments
    assert verify_secret(secret, commitments, RECOVERY_THRESHOLD)


def test_verify_invalid_secret():
    commitments = proof.commitments
    assert not verify_secret(secret + Scalar(1), commitments, RECOVERY_THRESHOLD)
