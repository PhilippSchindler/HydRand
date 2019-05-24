import dataclasses
import enum
import functools
import heapq
import hashlib
import logging
import math
import signal
import time as _time
import typing
# import warnings
import zmq

from collections import Counter
from typing import Dict, List, Optional

from hydrand import ed25519, pvss, merkle
from hydrand.config import (
    N,
    F,
    T,
    PROTOCOL_START_TIME,
    PROTOCOL_START_CONNECT_DELAY,
    ROUND_DURATION,
    PROPOSE_PHASE_DURATION,
    ACKNOWLEDGE_PHASE_DURATION,
    MAX_TIMEOUT,
    FAST_MODE_ENABLED,
    INITIAL_BEACON,
    NODE_ID,
    NUM_ROUNDS,
    LOG_FILE_PATH,
    load_config,
    NETWORK_CONFIG,
)
from hydrand.data import (
    AcknowledgeMessage,
    Confirmation,
    ConfirmationCertificate,
    ConfirmMessage,
    Dataset,
    DatasetHeader,
    get_message_type,
    get_message_sender,
    get_message_round,
    Hash,
    Message,
    MessageType,
    Phase,
    ProposeMessage,
    Serializer,
    Signature,
    SignedMessage,
    RecoverMessage,
    RecoveredShare,
    RecoveryCertificate,
    MIN_MESSAGE_SIZE,
    MAX_MESSAGE_SIZE,
)
from hydrand.ed25519 import Scalar, Point, KeyPair

NODE_INFOS = load_config()


@dataclasses.dataclass(order=True)
class MessageQueueItem:
    round: int
    phase: Phase
    timestamp: float
    content: bytes


class NodeStatus(enum.IntEnum):
    NORMAL = enum.auto()
    FAILED = enum.auto()
    ADVERSARIAL = enum.auto()


class Node:

    logger: logging.Logger

    ID: int
    KEYPAIR: KeyPair
    OTHER_PUBLIC_KEYS: List[Point]  # ordered list of all public keys from all other nodes, EXCLUDING self

    node_status: List[NodeStatus]

    # the node last shared secret (either from setup or from the last time the node was leader)
    shared_secret: Scalar

    # lists indexed by round index, automatically extended by a None element in the advance_round function
    beacons: List[Optional[Hash]]
    confirmation_certificates: List[Optional[ConfirmationCertificate]]
    recovery_certificates: List[Optional[RecoveryCertificate]]
    leaders: List[Optional[int]]
    revealed_secrets: List[Optional[Scalar]]
    datasets: List[Optional[Dataset]]

    propose_messages: List[Optional[ProposeMessage]]
    _acknowlegde_messages: List[Dict[int, AcknowledgeMessage]]
    _recover_messages: List[Dict[int, RecoverMessage]]
    _shares_for_recovery: List[Dict[int, Point]]
    _confirmations: List[List[Confirmation]]
    _confirmation_counters: List[typing.Counter[Hash]]
    sent_messages: List[SignedMessage]

    _round: int = 0
    _phase: Phase = Phase.Propose
    _last_confirmed_round: int = 0

    # the protocol start running at the begining of round 1
    # as soon as we advance from round 0 to round 1, _round_start is automatically advanced to PROTOCOL_START_TIME
    _t_round_start: float
    _t_round_end: float
    _t_ack_phase_start: float
    _t_vote_phase_start: float

    # a priority queue for processing messages in the correct order (by round, phase and time of arrival)
    _message_queue: List[MessageQueueItem]

    # low level ZMQ networking
    _send_socket: zmq.Socket  # PUB-socket for broadcasting to all connected nodes
    _recv_socket: zmq.Socket  # SUB-socket for receiving messages from ALL connected nodes
    _recv_poller: zmq.Poller  # poller for receiving message with specific timeouts

    listening: bool = False  # do not modify externally, if set the receive socket is active
    connected: bool = False  # do not modify externally, if set the send socket is active

    _running: bool = False
    _shutdown_requested: bool = False

    def __init__(self, node_id: Optional[int] = None):
        if node_id is None:
            assert NODE_ID is not None, "node_id must be specified in __init__ or in config"
            node_id = NODE_ID
            signal.signal(signal.SIGINT, self._shutdown)
            signal.signal(signal.SIGTERM, self._shutdown)
            signal.signal(signal.SIGHUP, self._shutdown)

        self.logger = logging.getLogger(f"NODE {node_id: <{len(str(N-1))}}")
        if NETWORK_CONFIG == 'amazon':
            self.logger.addHandler(logging.FileHandler(LOG_FILE_PATH, mode='w'))
            self.logger.propagate = False

        self._t_round_start = PROTOCOL_START_TIME - ROUND_DURATION
        self.ID = node_id
        self.KEYPAIR = NODE_INFOS[self.ID].keypair
        self.OTHER_PUBLIC_KEYS = [n.public_key for n in NODE_INFOS if n.id != self.ID]
        self.node_status = [NodeStatus.NORMAL] * N
        self.shared_secret = NODE_INFOS[self.ID].initial_secret
        self.beacons = [Hash(INITIAL_BEACON)]
        self.confirmation_certificates = [None]
        self.recovery_certificates = [None]
        self.leaders = [None]
        self.revealed_secrets = [None]
        self.datasets = [None]
        self.propose_messages = [None]
        self._acknowlegde_messages = [{}]
        self._confirmations = [[]]
        self._confirmation_counters = [Counter()]
        self._recover_messages = [{}]
        self._shares_for_recovery = [{}]
        self.sent_messages = []
        self._message_queue = []

    def run(self):
        """ Main entry point.
            Waits until the protocol should start and then runs the Hydrand protocol.

            returns True if the protocol was succesfully executed for NUM_ROUNDS
        """
        self.logger.info(f"THIS IS NODE: {self.ID}")
        self.logger.info("starting node")
        self.startup()
        self.logger.info("startup completed")

        while not self.shutdown_requested and self.round < NUM_ROUNDS:
            self._run_round()
        self.shutdown()

        self.logger.info("shutdown completed")
        return self.round == NUM_ROUNDS

    def run_round(self):
        """ Wrapper for _run_round, used for single stepping execution in tests only.
        """
        self._running = True
        self._run_round()
        self._running = False

    def _run_round(self):
        """ Executes one round of the protocol.
        """
        self.advance_round()  # increment round number and update timeouts
        self.compute_leader()

        if self.is_leader:
            self.propose()

        while not self.shutdown_requested:

            if self.update_phase():
                self.logger.info("PHASE CHANGED due to timeout")

                # The phase changed (i) from 'propose' to 'acknowlegde' or (ii) from 'acknowledge' to 'vote' due to
                # a timeout. In either case we ensure that we send out a recover message.
                self.recover()

            if self.virtual_round > self.round:
                # the current round has ended, according to clock information, so we can move to the next round
                assert self.beacon, "by assumption we must have a beacon value at this point"
                assert (
                    self.certificate_available
                ), "by assumption we must at least a confirmation certificate or a recovery certificate at this point"
                # TODO: maybe try to handle these cases gracefully
                break
            self.logger.debug("round=%d, virtual_time=%f, virtual_round=%d",
                              self.round, self.virtual_time(), self.virtual_round)

            if FAST_MODE_ENABLED and self.beacon and self.certificate_available:
                break

            # current round is not finished yet, so we try to process the next message from our queue,
            # - if there is no message for the current round and phase the following call returns False,
            #   and we wait for a new message or the end of the current phase (whichever comes first)
            # - otherwise the next message is processed
            if not self.process_message():
                self.receive_message(self.next_timeout())

    def startup(self):
        self.start_listening()
        self.logger.info("waiting for incomming connections")

        delta = PROTOCOL_START_TIME - PROTOCOL_START_CONNECT_DELAY - self.actual_time()
        assert delta > 0, ", ".join([
            f"late protocol start",
            f"delta={delta}",
            f"start_at={PROTOCOL_START_TIME}",
            f"connect_delay={PROTOCOL_START_CONNECT_DELAY}",
            f"time={self.actual_time()}",
        ])
        self.logger.info("waiting %.1f seconds until connecting to other nodes", delta)
        _time.sleep(delta)

        if self.shutdown_requested:
            return

        self.logger.info("connecting to other nodes")
        self.connect()

        delta = PROTOCOL_START_TIME - self.actual_time()
        self.logger.info("waiting %.1f seconds until protocol starts", delta)
        assert delta > 0, "late protocol start"
        _time.sleep(delta)

        if self.shutdown_requested:
            return

        self._running = True
        self.logger.info("protocol start")

    def shutdown(self):
        """ Stops the node gracefully.
            This call is not threadsafe, it must be executed from the same thread a the node was initialized with.
            This function cannot be used to stop a node which was started using run() but is useful for unit testing.
            To stop a node started using run(), execute a kill command for the process.
        """
        self._shutdown(None, None)
        self._running = False

    def _shutdown(self, signum=None, frame=None):
        """ Either called by shutdown() or via the registered signal handler (see __init__).
        """
        if not self.shutdown_requested:
            self.logger.info("shutdown initiated")

        self._shutdown_requested = True
        if self.connected:
            self.disconnect()
            self.stop_listening()

    @property
    def running(self):
        return self._running

    @property
    def shutdown_requested(self):
        return self._shutdown_requested

    ####################################################################################################################
    ####################################################################################################################
    # BEGIN RANDOMNESS BEACON
    ####################################################################################################################

    @property
    def beacon(self):
        return self.beacons[self.round]

    @property
    def prev_beacon(self):
        return self.beacons[self.round - 1]

    def compute_beacon(self, revealed_secret: Scalar = None, recovered_secret: Point = None):
        assert revealed_secret is not None or recovered_secret is not None
        assert not (revealed_secret and recovered_secret)

        if revealed_secret:
            gs = ed25519.Point.base_times(revealed_secret)
        else:
            assert recovered_secret is not None
            gs = recovered_secret

        beacon = hashlib.sha3_256(self.prev_beacon + bytes(gs)).digest()
        self.logger.info("NEW BEACON (round=%d): %s", self.round, beacon.hex())
        self.beacons[self.round] = Hash(beacon)

    ####################################################################################################################
    # END RANDOMNESS BEACON
    ####################################################################################################################
    ####################################################################################################################

    ####################################################################################################################
    ####################################################################################################################
    # BEGIN LEADER SELECTION
    ####################################################################################################################

    @property
    def leader(self):
        return self.leaders[self.round]

    @property
    def is_leader(self) -> bool:
        return self.leader == self.ID

    def compute_leader(self):
        R = int.from_bytes(self.prev_beacon, "little")
        rn = self._recovered_nodes(self.last_confirmed_round)
        P = {i: None for i in range(N)}  # make use of the fact that dicts are ordered in python now
        prev_leaders = self.leaders[max(1, self.round - F):self.round]

        self.logger.debug("running leader selection: excluding previous leaders %s", prev_leaders)
        for x in prev_leaders:
            del P[x]

        self.logger.debug("running leader selection: excluding failed nodes %s", rn)
        for x in rn:
            try:
                del P[x]
            except KeyError:
                pass
        Pcan = list(P.keys())
        self.leaders[self.round] = Pcan[R % len(Pcan)]
        self.logger.info("NODE %d leader is leader for this round (%d)", self.leader, self.round)
        if self.is_leader:
            self.logger.info("THIS NODE IS LEADER for this round (%d)", self.round)

    @functools.lru_cache(maxsize=1000)
    def _recovered_nodes(self, x: int):
        """ helper function rn(Dx) to recursively compute the set of recovered nodes from the view of a dataset
        """
        if x == 0:
            return set()
        Dx = self.datasets[x]
        assert Dx is not None
        xprev = Dx.prev_round_idx
        if xprev == x - 1:
            # no recovery certificates
            return self._recovered_nodes(xprev)
        return self._recovered_nodes(xprev) | {self.leaders[r] for r in range(xprev + 1, x)}

    ####################################################################################################################
    # END LEADER SELECTION
    ####################################################################################################################
    ####################################################################################################################

    ####################################################################################################################
    ####################################################################################################################
    # BEGIN DATASTORE ITEMS
    ####################################################################################################################

    @property
    def dataset(self):
        return self.datasets[self.round]

    @property
    def propose_message(self):
        return self.propose_messages[self.round]

    @property
    def acknowlegde_messages(self):
        return self._acknowlegde_messages[self.round]

    @property
    def recover_messages(self):
        return self._recover_messages[self.round]

    @property
    def confirmations(self):
        return self._confirmations[self.round]

    @property
    def confirmation_certificate(self):
        return self.confirmation_certificates[self.round]

    @property
    def confirmation_counter(self):
        return self._confirmation_counters[self.round]

    @property
    def recovery_certificate(self):
        return self.recovery_certificates[self.round]

    @property
    def certificate_available(self):
        return bool(self.confirmation_certificate or self.recovery_certificate)

    @property
    def last_confirmation_certificate(self):
        return self.confirmation_certificates[self.last_confirmed_round]

    @property
    def last_confirmed_round(self):
        return self._last_confirmed_round

    @property
    def shares_for_recovery(self):
        return self._shares_for_recovery[self.round]

    ####################################################################################################################
    # END DATASTORE ITEMS
    ####################################################################################################################
    ####################################################################################################################

    ####################################################################################################################
    ####################################################################################################################
    # BEGIN OUTGOING MESSAGES
    ####################################################################################################################

    def propose(self):
        self.compute_beacon(self.shared_secret)
        new_shared_secret, encrypted_shares, proof = pvss.share_random_secret(self.OTHER_PUBLIC_KEYS, T)
        dataset = Dataset(
            round_idx=self.round,
            prev_round_idx=self.last_confirmed_round,
            revealed_secret=self.shared_secret,
            beacon=self.beacon,
            recovered_beacons=self.beacons[self.last_confirmed_round + 1: self.round],
            merkle_root=merkle.compute_root([Hash(bytes(es)) for es in encrypted_shares]),
            encrypted_shares=encrypted_shares,
            proof=proof,
            confirmation_certificate=self.last_confirmation_certificate,
            recovery_certificates=self.recovery_certificates[self.last_confirmed_round + 1: self.round],
        )

        msg = ProposeMessage(
            sender=self.ID,
            dataset=dataset,
            dataset_header_signature=Signature.create_later(
                lambda: dataset.serialized_header, self.KEYPAIR.secret_key
            ),
            confirmation_certificate_signature=Signature.create_later(
                lambda: ConfirmMessage(self.ID, self.round, dataset.header_digest).serialize(),
                self.KEYPAIR.secret_key
            ),
        )
        self.broadcast_message(msg)
        self.datasets[self.round] = dataset
        self.shared_secret = new_shared_secret
        self.confirmations.append(Confirmation(self.ID, dataset.header_digest, msg.confirmation_certificate_signature))
        self.confirmation_counter.update([dataset.header_digest])
        self.update_phase(Phase.Vote)

    def acknowledge(self):
        self.update_phase(Phase.Acknowledge)

        assert self.propose_message
        assert self.dataset
        assert isinstance(self.dataset, Dataset)

        # tells the serializer to only serialize data from the header, but exclude dataset body
        self.dataset.header_only = True

        msg = AcknowledgeMessage(self.ID, self.dataset, self.propose_message.dataset_header_signature)
        self.broadcast_message(msg)

        # restore
        self.dataset.header_only = False

        self.acknowlegde_messages[self.ID] = msg

    def confirm(self):
        if self.phase == Phase.Vote:
            self.logger.debug("Skipping to send confirm message, already in voting phase.")
            return
        self.update_phase(Phase.Vote)
        msg = ConfirmMessage(sender=self.ID, round_idx=self.round, dataset_header_digest=self.dataset.header_digest)
        signed_msg = self.broadcast_message(msg)

        self.confirmations.append(Confirmation(self.ID, msg.dataset_header_digest, signed_msg.signature))
        self.confirmation_counter.update([msg.dataset_header_digest])

    def recover(self):
        if self.phase == Phase.Vote:
            self.logger.debug("Skipping to send recover message, already in voting phase.")
            return
        self.update_phase(Phase.Vote)
        share = self.lookup_share_for_recovery()
        msg = RecoverMessage(self.ID, self.round, self.create_recovery_certificate_signature(), share)
        self.broadcast_message(msg)
        self.recover_messages[self.ID] = msg

    def lookup_share_for_recovery(self) -> Optional[RecoveredShare]:
        prev_round_with_same_leader = self.round - 1
        while prev_round_with_same_leader > 0 and self.leaders[prev_round_with_same_leader] != self.leader:
            prev_round_with_same_leader -= 1

        # try to find the share for recovery
        if prev_round_with_same_leader == 0:
            prev_enc_shares = NODE_INFOS[self.leader].initial_shares
        else:
            prev_dataset = self.datasets[prev_round_with_same_leader]
            if prev_dataset is None or not isinstance(prev_dataset, Dataset):
                # we do not have the dataset at all, or only the header
                return None
            prev_enc_shares = prev_dataset.encrypted_shares

        share_idx = self.ID if self.ID < self.leader else self.ID - 1
        encrypted_share = prev_enc_shares[share_idx]
        decrypted_share = pvss.decrypt_share(encrypted_share, self.KEYPAIR.secret_scalar)
        proof = pvss.prove_share_decryption(
            decrypted_share, encrypted_share, self.KEYPAIR.secret_scalar, self.KEYPAIR.public_key
        )
        # TODO: check if hashing of s.value is required
        branch = merkle.compute_branch([s.value for s in prev_enc_shares], share_idx)

        # TODO: check if we have to include the encrypted share as well, or if the branch itself is sufficient for
        # verification
        return RecoveredShare(decrypted_share, proof, branch)

    def create_recovery_certificate_signature(self):
        s = Serializer(8)
        s.write_u32(MessageType.Recover)
        s.write_u32(self.round)
        return Signature(ed25519.sign_detached(s.buffer, self.KEYPAIR.secret_key))

    ####################################################################################################################
    # END OUTGOING MESSAGES
    ####################################################################################################################
    ####################################################################################################################

    ####################################################################################################################
    ####################################################################################################################
    # BEGIN PROCESSING OF INCOMMING MESSAGES
    ####################################################################################################################

    def process_message(self):
        """
            Trys to process the next message from the message queue.
            All past message at the beginning of the queue are skipped.
            If the next message is for some future round and phase, it is not processed and this call returns False.
            Otherwise, the next message is removed from the queue and processed, True is returned.
        """
        while True:
            if not self.next_message:
                return False

            # check if next message is in the past, and drop it
            if (self.next_message.round, self.next_message.phase) < (self.round, self.phase):
                (self.logger.debug if self.is_leader else self.logger.warning)(
                    "dropping past message from round %d / phase %s",
                    self.next_message.round, self.next_message.phase.name
                )
                self.drop_message()
            else:
                break

        # check if next message is in the future, and process it at a later point in time
        if (self.next_message.round, self.next_message.phase) > (self.round, self.phase):
            return False

        msg_item = self.dequeue_message()
        msg_type = get_message_type(msg_item.content)
        msg_sender = get_message_sender(msg_item.content)

        if msg_sender == self.leader and msg_type != MessageType.Propose:
            self.logger.warning(f"FLAGGING NODE {msg_sender} AS ADVERSARY, LEADER SENT DIFFERENT MESSAGE")
            self.flag_adversary(msg_sender)
            self.recover()
            return True

        signed_msg: SignedMessage = SignedMessage.deserialize(msg_item.content)
        msg = signed_msg.message  # signature was already verified prior to insertion into the message buffer
        assert msg.round_idx == self.round
        assert msg.type.to_phase() == self.phase

        # TODO: add try/except for deserialization, and flag leader as adversial upon failure

        self.logger.debug("processing %s message", msg_type.name)
        if msg_type == MessageType.Propose:
            self.process_propose(msg)
        elif msg_type == MessageType.Acknowledge:
            self.process_acknowledge(msg)
        elif msg_type == MessageType.Confirm:
            self.process_confirm(signed_msg)
        elif msg_type == MessageType.Recover:
            self.process_recover(msg)
        else:
            assert False, "message type not considered"

        return True

    def process_messages(self):
        while self.process_message():
            pass

    def process_propose(self, msg: ProposeMessage):
        """ Processes a receive propose message from some node.
            The outer message signature has already been verified, but the other signatures and all message-internal
            checks are performed in this function. This includes the check if the sender is actually leader of the
            current round.
            There are two potential outcomes:
            a) True, e.g. proposal valid: The proposed dataset and comfirmation signature from the leader are stored.
               (next steps: the round random beacon is computed and a acknowlegde message is sent)
            b) False, e.g. proposal invalid: The leader is flagged as adversial.
               A potentially valid reveal secret is stored.
               (next steps: send recover message (include the secret if the included one was valid))
        """
        dataset = msg.dataset

        if self.verify_revealed_secret(dataset.revealed_secret):
            self.revealed_secrets[self.round] = dataset.revealed_secret
            self.compute_beacon(msg.dataset.revealed_secret)
        else:
            self.flag_adversary(msg.sender)
            return False

        if not self.verify_proposal(msg):
            self.flag_adversary(msg.sender)
            return False

        if dataset.prev_round_idx > 0:
            stored_prev_cc = self.confirmation_certificates[dataset.prev_round_idx]
            if stored_prev_cc:
                assert dataset.confirmation_certificate
                assert stored_prev_cc.dataset_header_digest == dataset.confirmation_certificate.dataset_header_digest
            else:
                self.confirmation_certificates[dataset.prev_round_idx] = dataset.confirmation_certificate

        self.propose_messages[self.round] = msg
        self.datasets[self.round] = dataset
        if not self.beacon:
            self.compute_beacon(dataset.revealed_secret)
        self.acknowledge()

    def process_acknowledge(self, msg: AcknowledgeMessage):
        assert (
            self.dataset
        ), "There must be a propose message / dataset for this round, otherwise we would have skipped the ack phase"

        header = msg.dataset_header
        if not self.verify_dataset_header(header, msg.dataset_header_signature):
            self.flag_adversary(msg.sender)
            return
        if header.header_digest != self.dataset.header_digest:
            self.recover()
            return

        self.acknowlegde_messages[msg.sender] = msg
        self.logger.debug("%d acknowledge messages received in round %d", len(self.acknowlegde_messages), self.round)

        if len(self.acknowlegde_messages) == 2 * F:  # +1 is from the leaders proposal
            self.logger.info("sufficient acks received => confirming")
            self.confirm()

    def process_confirm(self, signed_msg: SignedMessage):
        assert isinstance(signed_msg.message, ConfirmMessage)
        msg: ConfirmMessage = signed_msg.message

        if self.confirmation_certificate:
            self.logger.debug("ignoring incomming confirmation message, certificate already available")
            return

        self.confirmations.append(Confirmation(msg.sender, msg.dataset_header_digest, signed_msg.signature))
        self.confirmation_counter.update([msg.dataset_header_digest])
        header_digest, num_confirms = self.confirmation_counter.most_common()[0]

        self.logger.debug("%d confirmations in round %d", num_confirms, self.round)
        if num_confirms >= F + 1:
            self.create_confirmation_certificate(header_digest)

    def process_recover(self, msg: RecoverMessage):
        if self.recovery_certificate and self.beacon:
            return

        if not self.verify_recovery_certificate_signature(
            msg.recovery_certificate_signature, NODE_INFOS[msg.sender].public_key
        ):
            self.flag_adversary(msg.sender)
            return

        self.recover_messages[msg.sender] = msg
        if len(self.recover_messages) == F + 1:
            self.create_recovery_certificate()

        rs = msg.recovered_share
        if rs:
            root_hash = self.lookup_merkle_root()
            share_idx = msg.sender if msg.sender < self.leader else msg.sender - 1
            enc_share = Point.from_bytes(merkle.get_leaf(rs.merkle_branch, share_idx, N - 1))

            # lookup dataset (header) for the leader
            # at least a header does exists
            if not merkle.verify_branch(rs.merkle_branch, root_hash, share_idx, N - 1):  # type: ignore
                return

            if not pvss.verify_decrypted_share(rs.share, enc_share, NODE_INFOS[msg.sender].public_key, rs.proof):
                self.flag_adversary(msg.sender)
                return

            self.shares_for_recovery[msg.sender] = rs.share
            self.logger.info("storing share for recovery, now %d shares in total", len(self.shares_for_recovery))

            if len(self.shares_for_recovery) == F + 1:
                secret = self.recover_shared_secret()
                self.compute_beacon(recovered_secret=secret)
        else:
            self.logger.warning("RECOVER MESSAGE DID NOT INCLUDE A SHARE")

    def lookup_merkle_root(self) -> Hash:
        prev_round_with_same_leader = self.round - 1
        while prev_round_with_same_leader > 0 and self.leaders[prev_round_with_same_leader] != self.leader:
            prev_round_with_same_leader -= 1

        if prev_round_with_same_leader == 0:
            return NODE_INFOS[self.leader].initial_merkle_root

        dataset = self.datasets[prev_round_with_same_leader]
        assert dataset, "there must be at least a dataset header at this point"
        return dataset.merkle_root

    def create_confirmation_certificate(self, dataset_header_digest: Hash):
        cc = ConfirmationCertificate(dataset_header_digest, [], [])
        for c in self.confirmations:
            if c.dataset_header_digest == dataset_header_digest:
                cc.signers.append(c.node_id)
                cc.signatures.append(c.signature)
        self.confirmation_certificates[self.round] = cc
        self._last_confirmed_round = self.round

    def recover_shared_secret(self):
        self.logger.warning("RECOVERING BEACON VALUE FOR ROUND %d, (LEADER: NODE %d FAILED)", self.round, self.leader)
        indexed_shares = []
        for node_id, share in self.shares_for_recovery.items():
            # share id is not equal to node_id
            # share id start at 1, and no share for leader!
            if node_id < self.leader:
                share_id = node_id + 1
            else:
                share_id = node_id
            indexed_shares.append((share_id, share))
        return pvss.recover(indexed_shares)

    def create_recovery_certificate(self):
        self.logger.warning("CREATING RECOVERY CERTIFICATE FOR ROUND %d, (LEADER: NODE %d FAILED)",
                            self.round, self.leader)
        self.recover_messages
        rc = RecoveryCertificate(signers=[], signatures=[])
        c = 0
        for rmsg in self.recover_messages.values():
            rc.signers.append(rmsg.sender)
            rc.signatures.append(rmsg.recovery_certificate_signature)
            c += 1
            if c == T:
                break
        assert c == T, "recovery certificate must consists of T = F + 1 signatures"
        self.recovery_certificates[self.round] = rc

    def verify_recovery_certificate_signature(self, signature: Signature, public_key: Point):
        s = Serializer(8)
        s.write_u32(MessageType.Recover)
        s.write_u32(self.round)
        return ed25519.verify_detached(s.buffer, signature.serialized, public_key)

    ####################################################################################################################
    # END PROCESSING OF INCOMMING MESSAGES
    ####################################################################################################################
    ####################################################################################################################

    ####################################################################################################################
    ####################################################################################################################
    # BEGIN VERIFICATION
    ####################################################################################################################

    def verify_raw_message(self, msg: bytes):
        """ Checks the validity of an incomming message prior to deserialization.
            Raises a ValueError if any of the checks fail.
        """
        if not (MIN_MESSAGE_SIZE < len(msg) < MAX_MESSAGE_SIZE):
            raise ValueError("Invalid message size!")

        msg_type = get_message_type(msg)  # yields a ValueError on invalid type
        msg_sender = get_message_sender(msg)  # yields a ValueError if sender is invalid
        msg_round = get_message_round(msg)

        if msg_round < self.round:
            raise ValueError(f"Message to late")

        if msg_round == self.round:
            if msg_type == MessageType.Propose and self.phase > Phase.Propose:
                raise ValueError(f"Message to late!")
            if msg_type == MessageType.Acknowledge and self.phase > Phase.Acknowledge:
                if not self.is_leader:
                    raise ValueError(f"Message to late!")
            elif self.is_leader and msg_type != MessageType.Confirm:
                raise ValueError("Leaders only process Confirm messages for current round!")

        if self.node_status[msg_sender] == NodeStatus.ADVERSARIAL:
            return ValueError("Message sender is an adversary!")

        # TODO: Drop message if some message of the same (type, round, sender)-combination
        #       was previously added to the queue.

        # Drop messages with invalid signatures
        if not ed25519.verify_attached(msg, NODE_INFOS[msg_sender].public_key):
            return ValueError("Signature check failed!")

        return True

    def verify_proposal(self, msg: ProposeMessage):
        dataset: Dataset = msg.dataset

        if not ed25519.verify_detached(
            dataset.serialized_header, msg.dataset_header_signature.serialized, NODE_INFOS[msg.sender].public_key
        ):
            return False

        # TODO: additional checks for proposal verification are requried
        return True

    def verify_dataset_header(self, header: DatasetHeader, header_signature: Signature):
        return all(
            [
                ed25519.verify_detached(
                    header.serialized_header, header_signature.serialized, NODE_INFOS[self.leader].public_key
                ),
                self.verify_revealed_secret(header.revealed_secret),
            ]
        )

    def verify_revealed_secret(self, revealed_secret: Scalar):
        """ Checks if the given revealed secret can successfully be verified against the value the leader previously
            committed itself to. The check also fails if the leader previously did not send the ProposeMessage to this
            node.
        """
        r = self.prev_round_with_same_leader
        if r:
            dataset = self.datasets[r]
            if dataset:
                proof = dataset.proof
        else:
            proof = NODE_INFOS[self.leader].initial_proof

        return proof is not None and pvss.verify_secret(revealed_secret, proof.commitments, T)

    ####################################################################################################################
    # END VERFICIATION
    ####################################################################################################################
    ####################################################################################################################

    ####################################################################################################################
    ####################################################################################################################
    # BEGIN TIME
    ####################################################################################################################

    @staticmethod
    def actual_time():
        """ Returns the current time in (fractional).
        """
        return _time.time()

    def virtual_time(self):
        """ Returns the current virtual time as continously increasing float.
            Before protocol start this value is negative.
            At the start of the 1st round this value is 1.0.
            At the middle of round 5 this value is ~5.5.
            At the end of round 5 this value is 5.99.
        """
        return (_time.time() - PROTOCOL_START_TIME) / ROUND_DURATION

    @property
    def round(self):
        """ Returns the current round number the node is operating in.
            Does not automatically increase, use advance_round() to move to the next round.
        """
        return self._round

    @property
    def prev_round_with_same_leader(self):
        """ Return the most recent round number in which the current leader was previously leader.
        """
        for r in range(self.round - 1, 0, -1):
            if self.leaders[r] == self.leader:
                return r
        return None

    @property
    def phase(self):
        return self._phase

    def advance_round(self):
        """ Increments the internal round number and phase.
            Must be called at to start a new round, including the protocol start itself (round 0 -> round 1).
            Also updates the internal times for round starts and ends to compute timeouts correctly.
            Extends rounds based lists by one None element.
        """
        self._round += 1
        self._phase = Phase.Propose
        self._t_round_start += ROUND_DURATION
        self._t_round_end = self._t_round_start + ROUND_DURATION
        self._t_ack_phase_start = self._t_round_start + PROPOSE_PHASE_DURATION
        self._t_vote_phase_start = self._t_ack_phase_start + ACKNOWLEDGE_PHASE_DURATION

        self.beacons.append(None)
        self.confirmation_certificates.append(None)
        self.recovery_certificates.append(None)
        self.leaders.append(None)
        self.revealed_secrets.append(None)
        self.datasets.append(None)
        self.propose_messages.append(None)

        self._acknowlegde_messages.append({})
        self._recover_messages.append({})
        self._shares_for_recovery.append({})
        self._confirmations.append([])
        self._confirmation_counters.append(Counter())
        self.logger.info(f"ROUND CHANGED, now in: round=%d, phase=%s", self.round, self.phase)

    def update_phase(self, new_phase: Optional[Phase] = None):
        """ If a new phase is specified, the current phase is updated to match the given phase.
            Otherwise, the phase is updated to the next phase if the current timeout was exceeded.
            Return True if the phase was changed and False otherwise.
        """
        if new_phase is None:
            if self._phase != Phase.Vote and self.next_timeout() == 0:
                self._phase = Phase(self._phase + 1)
                self.logger.info(f"PHASE CHANGED, now in: round=%d, phase=%s", self.round, self.phase)
                return True
            return False

        phase_changed = new_phase == self._phase
        if new_phase < self._phase:
            raise ValueError("Cannot move backwards in phases.")
        self._phase = new_phase

        if phase_changed:
            self.logger.info(f"PHASE CHANGED, now in: round=%d, phase=%s", self.round, self.phase)
        return phase_changed

    @property
    def virtual_round(self):
        """ Return the round number the node is operating in according to the current virtual time.
            As long as the syncroncy assumption is fulfilled, virtual_round <= round is ensured.
        """
        return math.ceil(self.virtual_time())

    def next_timeout(self):
        """ Return the number of (fractional) seconds to wait until a change to the next protocol phase should happen.
            Typically used in the main message receive loop, to ensure progress when no messages are received.
            Returns at most config.MAX_TIMEOUT to allow for proper termination (keep alive tick).
        """
        if self.phase == Phase.Propose:
            timeout = max(self._t_ack_phase_start - self.actual_time(), 0)
        elif self.phase == Phase.Acknowledge:
            timeout = max(self._t_vote_phase_start - self.actual_time(), 0)
        else:
            timeout = max(self._t_round_end - self.actual_time(), 0)

        if MAX_TIMEOUT:
            timeout = min(timeout, MAX_TIMEOUT)
        return timeout

    ####################################################################################################################
    # END TIME
    ####################################################################################################################
    ####################################################################################################################

    ####################################################################################################################
    ####################################################################################################################
    # BEGIN NETWORKING
    ####################################################################################################################

    def start_listening(self):
        """ Initialize subscribe socket to receive message from all other nodes.
        """
        assert not self.listening
        assert not self.connected
        ctx = zmq.Context.instance()
        self._recv_socket = ctx.socket(zmq.SUB)
        self._recv_poller = zmq.Poller()
        self._recv_socket.setsockopt(zmq.SUBSCRIBE, b"")
        self._recv_poller.register(self._recv_socket, zmq.POLLIN)
        for i in range(N):
            if i != self.ID:
                address = NODE_INFOS[i].address
                port = NODE_INFOS[i].port
                self._recv_socket.connect(f"tcp://{address}:{port}")
        self.listening = True

    def connect(self):
        """ Initialize publisher socket to broadcast messages to all other nodes.
        """
        assert self.listening
        assert not self.connected
        ctx = zmq.Context.instance()
        port = NODE_INFOS[self.ID].port
        self._send_socket = ctx.socket(zmq.PUB)
        self._send_socket.bind(f"tcp://*:{port}")
        self.connected = True

    def disconnect(self):
        assert self.listening
        assert self.connected
        self._send_socket.close()
        self._send_socket = None
        self.connected = False

    def stop_listening(self):
        assert self.listening
        assert not self.connected
        self._recv_poller.unregister(self._recv_socket)
        self._recv_socket.close()
        self._recv_poller = None
        self._recv_socket = None
        self.listening = False

    def enqueue_message(self, item: MessageQueueItem):
        """ Adds a new message to the message queue.
        """
        heapq.heappush(self._message_queue, item)

    @property
    def next_message(self) -> Optional[MessageQueueItem]:
        """ Returns the next message from the message queue without removing it.
        """
        if self._message_queue:
            return self._message_queue[0]
        return None

    def dequeue_message(self) -> MessageQueueItem:
        """ Returns the next message from the message queue and removes it from the queue.
        """
        return heapq.heappop(self._message_queue)

    def drop_message(self):
        """ Removes the next message from the message queue.
        """
        heapq.heappop(self._message_queue)

    def broadcast_message(self, msg: Message) -> SignedMessage:
        """ Signs, serializes and broadcasts the given message.
            (A ProposeMessage requires an additional signer on the message header, as well as
            the signature for the confirmation certificate over the dataset header and body.
            Both are which is also added to the message.)
        """
        signed_msg = SignedMessage(msg, Signature.create_later(lambda: msg.serialized, self.KEYPAIR.secret_key))
        self._send_socket.send(signed_msg.serialize())
        self.logger.debug(
            "%s message broadcasted (round=%d, size=%.2fKB)",
            signed_msg.message.type.name.lower(),
            signed_msg.message.round_idx,
            len(signed_msg.serialized) / 1024
        )
        self.sent_messages.append(signed_msg)

        return signed_msg

    def receive_message(self, timeout: Optional[float] = None) -> bool:
        """ Wait for a new incomming message or a timeout, whichever comes first.
            If a message is received, preprocessing checks (i.e. msg size, type, ...) are performed.
            If a message is considered valid it is added to the message queue and True is returned.
            If a timeout occurres False is returned.
            If any of the message preprocessing checks fails, a ValueError is raised.
            The call is blocking until a specified timeout is reached or a message is received.
        """
        self.logger.debug("waiting for incomming message (timeout=%f seconds)", timeout)
        message_bytes = self.receive_bytes(timeout)
        if not message_bytes:
            self.logger.debug("message receive timeout")
            return False

        msg_round = get_message_round(message_bytes)
        msg_type = get_message_type(message_bytes)
        msg_sender = get_message_sender(message_bytes)
        self.logger.debug(f"{msg_type.name.lower()} message received: round={msg_round}, sender={msg_sender}")

        try:
            self.verify_raw_message(message_bytes)
            self.enqueue_message(
                MessageQueueItem(
                    round=msg_round,
                    phase=msg_type.to_phase(),
                    timestamp=self.actual_time(),
                    content=message_bytes,
                )
            )
            return True
        except ValueError as e:
            self.logger.debug(e)
            return False

    def receive_messages(self):
        while self.receive_message(timeout=0.0):
            pass

    def receive_bytes(self, timeout: Optional[float] = None) -> Optional[bytes]:
        """ Wait at most 'timeout' (fractional) seconds for a incomming message.
            Returns the raw bytes for a incomming message or None if the timeout is exceeded.
            The call is blocking until a specified timeout is reached or a message is received.
        """
        if timeout is None:
            return self._recv_socket.recv()

        # * 1000 as ms required here but seconds are used everywhere else
        if self._recv_poller.poll(timeout * 1000):
            return self._recv_socket.recv(flags=zmq.NOBLOCK)
        return None

    ####################################################################################################################
    # END NETWORKING
    ####################################################################################################################
    ####################################################################################################################

    def flag_adversary(self, node_id: int):
        if self.node_status[node_id] != NodeStatus.ADVERSARIAL:
            self.node_status[node_id] = NodeStatus.ADVERSARIAL
            self.logger.warning("flagging node %d as adversarial", node_id)
