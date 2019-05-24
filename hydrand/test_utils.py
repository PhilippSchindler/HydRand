import subprocess
import logging
import time

from typing import List
from hydrand.node import Node


class OpResult:

    def __new__(cls, values):
        instance = object.__new__(cls)
        instance.values = values
        instance.all_equal = all_equal(values)
        if instance.all_equal:
            if values[0] is None or values[0] is True or values[0] is False:
                return values[0]
            instance.value = values[0]
        return instance

    @property
    def all_none(self):
        return all([v is None for v in self.values])

    @property
    def all_not_none(self):
        return all([v is not None for v in self.values])

    def __eq__(self, other):
        if isinstance(other, OpResult):
            return self.values == other.values
        if isinstance(other, list):
            if self.values == other:
                return True
            if self.all_equal and self.value == other:
                return True
            return False
        assert self.all_equal, \
            "all nodes must return the same value if a comparsion with a value (and not a list) is used"
        return self.value == other

    def __iter__(self):
        return iter(self.values)

    def __ne__(self, other):
        return not (self == other)

    def __repr__(self):
        return f"OpResult({repr(self.values)})"

    def __bool__(self):
        assert False, "should not be called on OpResult"


class AnyNode(Node):
    def __init__(self, nodes: List[Node]):
        self.nodes = nodes

    def __getattribute__(self, name):
        if name == "nodes":
            return object.__getattribute__(self, name)

        attr = getattr(self.nodes[0], name)
        if hasattr(attr, "__call__"):

            def mux_func(*args, **kwargs):
                return OpResult([getattr(n, name)(*args, **kwargs) for n in self.nodes])

            return mux_func
        else:
            return OpResult([getattr(n, name) for n in self.nodes])


class LeaderNode(Node):
    def __init__(self, nodes: List[Node]):
        self.nodes = nodes

    def __getattribute__(self, name):
        if name == "nodes":
            return object.__getattribute__(self, name)

        leaders = [n for n in self.nodes if n.is_leader]
        assert len(leaders) == 1
        return getattr(leaders[0], name)


class NoLeaderNode(Node):
    def __init__(self, nodes: List[Node]):
        self.nodes = nodes

    def __getattribute__(self, name):
        if name == "nodes":
            return object.__getattribute__(self, name)

        attr = getattr(self.nodes[0], name)
        if hasattr(attr, "__call__"):

            def mux_func(*args, **kwargs):
                return OpResult([getattr(n, name)(*args, **kwargs) for n in self.nodes if not n.is_leader])

            return mux_func
        else:
            return OpResult([getattr(n, name) for n in self.nodes if not n.is_leader])

    def __iter__(self):
        return (n for n in self.nodes if not n.is_leader)


def all_equal(items):
    item = items[0]
    for i in items[1:]:
        if i != item:
            return False
    return True


def all_equal_to(items, target):
    for item in items:
        if item == target:
            continue
        return False
    return True


def all_none(items):
    for item in items:
        if item is not None:
            return False
    return True


def force_close_port(port=5000):
    """ issues a kill -9 command on a process using the specified port
    """
    result = subprocess.run(
        f"netstat -np | grep -m1 -E -o ':[0-9]+.*:{port}[^0-9]*([0-9]+)'", shell=True, capture_output=True)
    if result.stdout:
        pid = result.stdout.split()[-1].decode()
        kill_cmd = f"kill -9 {pid}"
        kill_result = subprocess.run(kill_cmd, shell=True)
        assert kill_result.returncode == 0, f"'{kill_cmd}' failed"
        logging.warning(f"process {pid} was killed to release ports")
        time.sleep(1)
