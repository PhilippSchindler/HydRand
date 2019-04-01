from hydrand import pvss, utils, ed25519, merkle
from hydrand.ed25519 import KeyPair, Scalar, Point
from hydrand.data import Serializer, MessageType, RecoverMessage, RecoveredShare, DatasetHeader, Hash, Signature
import time

from hydrand.config import N, T, F

assert N == 128, "set i.e. N=128 before running this file in config.py"

keypairs = [KeyPair.random() for i in range(N - 1)]
public_keys = [k.public_key for k in keypairs]
shared_secret, encrypted_shares, proofs = pvss.share_random_secret(public_keys, T)
decrypted_shares = [pvss.decrypt_share(share, keypair.secret_scalar)
                    for share, keypair in zip(encrypted_shares, keypairs)]

dataset_header = DatasetHeader(
    round_idx=4711,
    prev_round_idx=4710,
    revealed_secret=Scalar.random(),
    beacon=Hash(utils.deterministic_random_bytes(32, "some beacon")),
    recovered_beacons=[],
    merkle_root=merkle.compute_root([Hash(bytes(es)) for es in encrypted_shares])
)

decryption_proofs = [
    pvss.prove_share_decryption(
        decrypted_share, encrypted_share, keypair.secret_scalar, keypair.public_key
    )
    for decrypted_share, encrypted_share, keypair in
    zip(decrypted_shares, encrypted_shares, keypairs)
]
merkle_branches = [
    merkle.compute_branch(
        [Hash(bytes(s.value)) for s in encrypted_shares],
        share_idx
    )
    for share_idx, _ in enumerate(encrypted_shares)
]

serialized = dataset_header.serialize()


def create_recovery_certificate_signature(keypair, rnd):
    s = Serializer(8)
    s.write_u32(MessageType.Recover)
    s.write_u32(rnd)
    return Signature(ed25519.sign_detached(s.buffer, keypair.secret_key))


def verify_recovery_certificate_signature(self, signature, public_key, rnd):
    s = Serializer(8)
    s.write_u32(MessageType.Recover)
    s.write_u32(rnd)
    return ed25519.verify_detached(s.buffer, signature.serialized, public_key)


recovery_cert_sigs = [create_recovery_certificate_signature(keypair, 4711) for keypair in keypairs]
recover_messages = [
    RecoverMessage(
        i + 1,
        4711,
        create_recovery_certificate_signature(keypair, 4711),
        RecoveredShare(decrypted_share, proof, branch)
    )
    for i, (keypair, decrypted_share, proof, branch) in
    enumerate(zip(keypairs, decrypted_shares, decryption_proofs, merkle_branches))
][: F + 1]

rec_messages_bin = [r.serialize() for r in recover_messages]
rec_messages_sigs = [ed25519.sign_detached(m, keypair.secret_key) for m, keypair in zip(rec_messages_bin, keypairs)]


def get_verification_time_approx():
    t_start = time.time()
    for msg, sig, keypair in zip(rec_messages_bin, rec_messages_sigs, keypairs):
        assert ed25519.verify_detached(msg, sig, keypair.public_key)
    t_end = time.time()
    t_sigchecks = 2 * (t_end - t_start)  # 2x to account for signature checks in confirmation certificates

    t_start = time.time()

    indexed_shares = [(i + 1, share) for i, share in enumerate(decrypted_shares[:F + 1])]
    secret = pvss.recover(indexed_shares)
    assert secret == Point.B * shared_secret

    for i, branch in enumerate(merkle_branches[:F + 1]):
        assert merkle.verify_branch(branch, dataset_header.merkle_root, i, N - 1)

    for keypair, enc_share, msg in zip(keypairs, encrypted_shares, recover_messages):
        rs = msg.recovered_share
        assert pvss.verify_decrypted_share(rs.share, enc_share, keypair.public_key, rs.proof)

    t_end = time.time()
    return t_sigchecks + (t_end - t_start)


t_avg = sum(get_verification_time_approx() for _ in range(1000)) / 1000
print(f"verification time (worst case) for N={N}: {t_avg * 1000} ms")
print()

dh = len(serialized)  # header size
dc = (F + 1) * 64  # confirmation certificate signatures
dr = (F + 1) * (len(recover_messages[0].serialize()) + 64 + 32)     # recover messages
d = dh + dc + dr
print(f"data required for verification (worst case): {d / 1000} kB")
print(f"header: {dh / 1000} kB")
print(f"confirmation certificate: {dc / 1000} kB")
print(f"recovery messages: {dr / 1000} kB")
