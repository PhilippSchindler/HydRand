import itertools
import pytest
import random
import secrets

from hydrand import merkle, utils
from hydrand.data import (
    Hash,
    RecoveryCertificate,
    ConfirmationCertificate,
    ShareCorrectnessProof,
    ShareDecryptionProof,
    RecoveredShare,
    DatasetHeader,
    Dataset,
    ProposeMessage,
    AcknowledgeMessage,
    ConfirmMessage,
    RecoverMessage,
    SignedMessage,
    Signature,
)
from hydrand.ed25519 import Scalar, Point, verify_attached, verify_detached

from hydrand.config import N, F


# fmt: off

def get(obj_type, num_elements=None, **kwargs):
    mapping = {
        Scalar: lambda: Scalar.random(),
        Point: lambda: Point.base_times(Scalar.random()),
        Hash: lambda: Hash(secrets.token_bytes(32)),
        Signature: lambda: Signature(secrets.token_bytes(64)),
        RecoveryCertificate:
            lambda: RecoveryCertificate(
                signers=random.sample(list(range(N)), F + 1),
                signatures=get(Signature, F + 1),
        ),
        ConfirmationCertificate:
            lambda: ConfirmationCertificate(
                dataset_header_digest=get(Hash),
                signers=random.sample(list(range(N)), F + 1),
                signatures=get(Signature, F + 1),
        ),
        ShareCorrectnessProof:
            lambda: ShareCorrectnessProof(
                commitments=get(Point, N - 1),
                challenge=get(Scalar),
                responses=get(Scalar, N - 1),
        ),
        ShareDecryptionProof:
            lambda: ShareDecryptionProof(
                challenge=get(Scalar),
                response=get(Scalar),
        ),
        RecoveredShare:
            lambda: RecoveredShare(
                share=get(Point),
                proof=get(ShareDecryptionProof),
                merkle_branch=get(Hash, merkle.branch_length(N - 1)),
        ),
        DatasetHeader:
            lambda **kws: DatasetHeader(
                round_idx=kws['round_idx'],
                prev_round_idx=kws['prev_round_idx'],
                revealed_secret=get(Scalar),
                beacon=get(Hash),
                recovered_beacons=get(Hash, kws['round_idx'] - kws['prev_round_idx'] - 1),
                merkle_root=get(Hash),
        ),
        Dataset:
            lambda **kws: Dataset(
                round_idx=kws['round_idx'],
                prev_round_idx=kws['prev_round_idx'],
                revealed_secret=get(Scalar),
                beacon=get(Hash),
                recovered_beacons=get(Hash, kws['round_idx'] - kws['prev_round_idx'] - 1),
                merkle_root=get(Hash),
                encrypted_shares=get(Point, N - 1),
                proof=get(ShareCorrectnessProof),
                confirmation_certificate=None if kws['prev_round_idx'] == 0 else get(ConfirmationCertificate),
                recovery_certificates=get(RecoveryCertificate, kws['round_idx'] - kws['prev_round_idx'] - 1),
        ),
        ProposeMessage:
            lambda **kws: ProposeMessage(
                sender=random.randint(0, N - 1),
                dataset=get(Dataset, **kws),
                dataset_header_signature=get(Signature),
                confirmation_certificate_signature=get(Signature),
        ),
        AcknowledgeMessage:
            lambda **kws: AcknowledgeMessage(
                sender=random.randint(0, N - 1),
                dataset_header=get(DatasetHeader, **kws),
                dataset_header_signature=get(Signature),
        ),
        ConfirmMessage:
            lambda **kws: ConfirmMessage(
                sender=random.randint(0, N - 1),
                round_idx=kws.get('round_idx', random.randint(0, 1000_000)),
                dataset_header_digest=get(Hash),
        ),
        RecoverMessage:
            lambda **kws: RecoverMessage(
                sender=random.randint(0, N - 1),
                round_idx=kws.get('round_idx', random.randint(0, 1000_000)),
                recovery_certificate_signature=get(Signature),
                recovered_share=get(RecoveredShare) if kws.get('add_recovered_share', True) else None
        ),
        SignedMessage:
            lambda **kws: SignedMessage(
                message=get(kws['msg_type'], **kws),
                signature=get(Signature),
        )
    }
    if num_elements is None:
        return mapping[obj_type](**kwargs)
    return [mapping[obj_type](**kwargs) for _ in range(num_elements)]

# fmt: on


# TODO: add Dataset test
# TODO: add SignedMessage test


@pytest.mark.parametrize(
    "obj_type",
    [RecoveryCertificate, ConfirmationCertificate, ShareCorrectnessProof, ShareDecryptionProof, RecoveredShare],
)
def test_serialization(obj_type):
    v = get(obj_type)
    assert obj_type.deserialize(v.serialize()) == v


@pytest.mark.parametrize(
    "obj_type, kwargs",
    itertools.product(
        [DatasetHeader, Dataset, ProposeMessage, AcknowledgeMessage, ConfirmMessage, RecoverMessage],
        [
            {"round_idx": 10, "prev_round_idx": 7},
            {"round_idx": 10, "prev_round_idx": 9},
            {"round_idx": 1, "prev_round_idx": 0},
            {"round_idx": 5, "prev_round_idx": 0},
        ],
    ),
)
def test_serialization_round_specific(obj_type, kwargs):
    v = get(obj_type, **kwargs)
    assert obj_type.deserialize(v.serialize()) == v


@pytest.mark.parametrize(
    "msg_type, kwargs",
    itertools.product(
        [ProposeMessage, AcknowledgeMessage, ConfirmMessage, RecoverMessage],
        [
            {"round_idx": 10, "prev_round_idx": 7},
            {"round_idx": 10, "prev_round_idx": 9},
            {"round_idx": 1, "prev_round_idx": 0},
            {"round_idx": 5, "prev_round_idx": 0},
        ],
    ),
)
def test_serialization_signed_message(msg_type, kwargs):
    v = get(SignedMessage, msg_type=msg_type, **kwargs)
    assert SignedMessage.deserialize(v.serialize()) == v


def test_serialization_no_recovered_share():
    v = get(RecoverMessage, add_recovered_share=False)
    assert v.recovered_share is None
    assert RecoverMessage.deserialize(v.serialize()) == v


def test_signature_verification():
    keypair = utils.determinisitic_random_keypair(0)
    msg = ConfirmMessage(sender=0, round_idx=1, dataset_header_digest=get(Hash))
    signed_msg = SignedMessage(msg, Signature.create_later(lambda: msg.serialized, keypair.secret_key))
    data = signed_msg.serialize()
    received_msg = SignedMessage.deserialize(data)
    assert verify_attached(data, keypair.public_key)
    assert verify_detached(received_msg.message.serialized, received_msg.signature.serialized, keypair.public_key)
    assert received_msg.verify_signature(keypair.public_key)
    assert verify_attached(bytes(data), keypair.public_key)
