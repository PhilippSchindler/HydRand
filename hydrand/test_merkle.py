import pytest
import random
import math

from hydrand.merkle import compute_root, compute_branch, verify_branch, get_leaf

random.seed(0)
B = [i.to_bytes(1, "little") for i in range(256)]


def test_compose():
    L = compute_root(B[0:4])
    R = compute_root(B[4:8])
    assert compute_root([L, R]) == compute_root(B[0:8])


def test_compose_uneven():
    L = compute_root(B[0:4])
    R = compute_root(B[4:7])
    assert compute_root([L, R]) == compute_root(B[0:7])


@pytest.mark.parametrize("leaves", [B[:i] for i in [2 ** j for j in range(9)]])
def test_branch_power_of_two(leaves):
    root = compute_root(leaves)
    for i in range(len(leaves)):
        branch = compute_branch(leaves, i)
        assert leaves[i] in branch
        assert get_leaf(branch, i, len(leaves)) == leaves[i]
        assert verify_branch(branch, root, i, len(leaves))


@pytest.mark.parametrize("leaves", [B[:i] for i in range(1, 257)])
def test_branch_power_all(leaves):
    root = compute_root(leaves)
    for i in range(len(leaves)):
        branch = compute_branch(leaves, i)
        assert leaves[i] in branch
        assert get_leaf(branch, i, len(leaves)) == leaves[i]
        assert len(branch) == math.ceil(math.log2(len(leaves))) + 1
        assert verify_branch(branch, root, i, len(leaves))


# @pytest.mark.parametrize("leaves", [B[:i] for i in range(1, 257)])
# def test_branch_power_all_extened(leaves):
#     root = compute_root(leaves)
#     for i in range(len(leaves)):
#         branch = compute_branch(leaves, i)
#         branch.append(b"some unnessary stuff")
#         assert verify_branch(branch, root, i, len(leaves))
