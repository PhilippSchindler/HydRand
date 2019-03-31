import math

from typing import List, NewType
from hashlib import sha256

# from hydrand.data import Hash

Hash = NewType("Hash", bytes)


def compute_root(data: List[Hash], start=None, end=None):

    if start is None:
        start = 0
        end = len(data)

    length = end - start
    if length == 1:
        return data[start]
    if length == 2:
        L = data[start]
        R = data[start + 1]
    else:
        split_offset = next_power_of_two(length) >> 1
        L = compute_root(data, start, start + split_offset)
        R = compute_root(data, start + split_offset, end)

    h = sha256(L)  # type: ignore
    h.update(R)  # type: ignore
    return Hash(h.digest())


def compute_branch(data: List[Hash], target: int) -> List[Hash]:
    result: List[Hash] = []
    _compute_branch(data, target, result)

    x = 1
    p = 0
    while x < len(data):
        x <<= 1
        p += 1
    p += 1
    b = b"\x00" * 32
    while len(result) < p:
        result.append(Hash(b))
    return result


def branch_length(n):
    return math.ceil(math.log2(n)) + 1


def _compute_branch(data: List[Hash], target: int, result: List[Hash]):
    if target >= len(data):
        raise ValueError()

    if len(data) == 1:
        result.append(data[0])
        return

    n = next_power_of_two(len(data))
    if target < n // 2:
        _compute_branch(data[: n // 2], target, result)
        result.append(compute_root(data[n // 2:]))
    else:
        result.append(compute_root(data[: n // 2]))
        _compute_branch(data[n // 2:], target - n // 2, result)


def verify_branch(branch: List[Hash], root: bytes, target: int, num_leaves: int):
    val, _ = _eval_branch(branch, target, 0, num_leaves, 0)
    return root == val


def get_leaf(branch: List[Hash], target: int, num_leaves: int) -> Hash:
    S = next_power_of_two(num_leaves)
    p = 0
    while S != 1:
        S //= 2
        if target >= S:
            target -= S
            p += 1
    return branch[p]


def _eval_branch(branch: List[Hash], target: int, start: int, end: int, pos: int):
    # print()
    # print(f"target={target}; start={start}; end={end}; pos={pos}")

    length = end - start
    if length == 1:
        # print("return len == 1")
        return branch[pos], pos + 1

    if length == 2:
        # print("return len == 2")
        L = branch[pos]
        R = branch[pos + 1]
        pos += 2

    else:
        split_offset = start + (next_power_of_two(length) >> 1)
        if target < split_offset:
            # print("going left...")
            L, pos = _eval_branch(branch, target, start, split_offset, pos)
            R = branch[pos]
            pos += 1
        else:
            # print("going right...")
            L = branch[pos]
            R, pos = _eval_branch(branch, target, split_offset, end, pos + 1)

    h = sha256(L)  # type: ignore
    h.update(R)  # type: ignore
    return Hash(h.digest()), pos


def next_power_of_two(v: int):
    """ returns x | x == 2**i and x >= v """
    v -= 1
    v |= v >> 1
    v |= v >> 2
    v |= v >> 4
    v |= v >> 8
    v |= v >> 16
    v += 1
    return v
