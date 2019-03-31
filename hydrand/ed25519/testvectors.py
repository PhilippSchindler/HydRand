import os
import dataclasses

TEST_VECTORS = []
TEST_VECTORS_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "testvectors.txt"))


@dataclasses.dataclass
class TestVector:
    seed: bytes
    public_key: bytes
    message: bytes
    signed_message: bytes
    signature: bytes

    __test__ = False


with open(TEST_VECTORS_PATH, "r") as f:
    for line in f.read().splitlines():
        args = [bytes.fromhex(arg) for arg in line.split(":")]
        TEST_VECTORS.append(
            TestVector(
                seed=args[0][:32], public_key=args[1], message=args[2], signed_message=args[3], signature=args[3][:64]
            )
        )

