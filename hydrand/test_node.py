import pytest
from typing import List
from threading import Thread

from hydrand.config import N
from hydrand.node import Node

from hydrand.test_utils import AnyNode, LeaderNode, NoLeaderNode, force_close_port

node: AnyNode  # any call to this node is multiplexed to all other nodes
leader: LeaderNode
noleader: NoLeaderNode
nodes: List[Node]


@pytest.fixture(autouse=True)
def nodes_setup_and_teardown():
    global node, nodes, leader, noleader
    force_close_port(5000)
    nodes = [Node(i) for i in range(N)]
    node = AnyNode(nodes)
    leader = LeaderNode(nodes)
    noleader = NoLeaderNode(nodes)


def test_run():
    threads = [Thread(target=n.run) for n in nodes]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
