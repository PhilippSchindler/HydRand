import pytest
import time
# import logging
from typing import List
from threading import Thread

from hydrand.config import N
from hydrand.data import Phase
from hydrand.node import Node

from hydrand.test_utils import AnyNode, LeaderNode, NoLeaderNode, force_close_port

import hydrand.node as node_module


STARTUP_DELAY = 5.0

node: AnyNode  # any call to this node is multiplexed to all other nodes
leader: LeaderNode
noleader: NoLeaderNode
nodes: List[Node]


@pytest.fixture(autouse=True)
def nodes_setup_and_teardown():
    global node, nodes, leader, noleader
    force_close_port(5000)

    node_module.PROTOCOL_START_TIME = time.time() + STARTUP_DELAY
    nodes = [Node(i) for i in range(N)]

    node = AnyNode(nodes)
    leader = LeaderNode(nodes)
    noleader = NoLeaderNode(nodes)

    node.start_listening()
    time.sleep(STARTUP_DELAY / 2)
    node.connect()
    time.sleep(STARTUP_DELAY / 2)

    yield
    print("TEST TEARDOWN")
    node.shutdown()


def test_start_nodes():
    assert node.round == 0
    assert node.phase == Phase.Propose
    assert node.connected


def test_initial_round_leader():
    node.advance_round()
    node.compute_leader()
    assert node.leaders.all_equal


def test_propose_basics():
    node.advance_round()
    node.compute_leader()
    leader.propose()

    assert leader.phase == Phase.Vote
    assert noleader.phase == Phase.Propose

    assert noleader.next_message is None
    noleader.receive_message()
    assert all(noleader.next_message.values)

    assert noleader.process_message()
    assert noleader.phase == Phase.Acknowledge

    assert node.beacon.all_equal


def test_reveal_verification():
    node.advance_round()
    node.compute_leader()
    leader.propose()
    signed_msg = leader.sent_messages[0]
    msg = signed_msg.message
    dataset = msg.dataset
    assert leader.verify_revealed_secret(dataset.revealed_secret)
    assert noleader.verify_revealed_secret(dataset.revealed_secret)


def test_round_step():

    node.advance_round()
    node.compute_leader()

    leader.propose()
    noleader.receive_messages()
    noleader.process_message()  # acks are sent here

    assert noleader.phase == Phase.Acknowledge
    node.receive_messages()
    for n in noleader:
        assert len(n._message_queue) == N - 2
    assert len(leader._message_queue) == N - 1
    node.process_messages()  # confirms are sent here

    node.receive_messages()
    node.process_messages()


def test_2rounds_step():
    node.advance_round()
    node.compute_leader()

    leader.propose()

    node.receive_messages()
    node.process_messages()  # sends out acks

    node.receive_messages()
    node.process_messages()  # sends out confirms

    node.receive_messages()
    node.process_messages()

    # all nodes have beacon and confirmation certificate here

    node.advance_round()
    node.compute_leader()

    assert node.leader.all_equal
    assert node.round == 2

    leader.propose()
    node.receive_messages()
    node.process_messages()


def test_run_round():
    threads = [Thread(target=n.run_round) for n in nodes]
    for t in threads:
        t.start()

    for t in threads:
        t.join()

    assert node.beacon.all_equal
    assert node.beacon is not None

    for cc in node.confirmation_certificate:
        assert cc is not None


def test_recover_first_round():
    node.advance_round()
    node.compute_leader()

    leader.compute_beacon(leader.shared_secret)

    node.update_phase()
    noleader.recover()

    noleader.receive_messages()
    noleader.process_messages()

    assert node.beacon.all_equal
