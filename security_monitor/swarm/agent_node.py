import hashlib
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from security_monitor.swarm.consensus import resolve_commit
from security_monitor.swarm.execution import execute_task
from security_monitor.swarm.fault_injector import FaultInjector
from security_monitor.swarm.messages import (
    BID,
    COMMIT_VOTE,
    DISCOVER,
    EXEC_DONE,
    EXEC_START,
    HEARTBEAT,
    TASK_OFFER,
    THREAT_GOSSIP,
    VERIFY_ACK,
    EventRecord,
)
from security_monitor.swarm.negotiation import select_winner
from security_monitor.swarm.security import ReplayProtector, sign_payload, verify_payload


@dataclass
class AgentNode:
    agent_id: str
    capability: str
    secret: str
    bid_profile: Dict[str, Any]
    network: "SwarmNetwork"
    is_planner: bool = False
    active: bool = True
    peers: Dict[str, float] = field(default_factory=dict)
    offers: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    bids_by_task: Dict[str, List[Dict[str, Any]]] = field(default_factory=dict)
    votes_by_task: Dict[str, List[Dict[str, Any]]] = field(default_factory=dict)
    committed_winner_by_task: Dict[str, str] = field(default_factory=dict)
    executions: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    verify_acks_by_task: Dict[str, Dict[str, str]] = field(default_factory=dict)
    threat_ledger: Dict[str, str] = field(default_factory=dict)  # Hive Memory: threat_id -> threat_details
    replay: ReplayProtector = field(default_factory=ReplayProtector)
    _nonce: int = 0

    def _next_nonce(self) -> str:
        self._nonce += 1
        return f"{self.agent_id}-{self._nonce}"

    def _build_envelope(self, message_type: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        envelope = {
            "type": message_type,
            "sender": self.agent_id,
            "ts": time.time(),
            "nonce": self._next_nonce(),
            "payload": payload,
        }
        signing_data = {
            "type": envelope["type"],
            "sender": envelope["sender"],
            "ts": envelope["ts"],
            "nonce": envelope["nonce"],
            "payload": envelope["payload"],
        }
        envelope["sig"] = sign_payload(self.secret, signing_data)
        return envelope

    def _broadcast(self, message_type: str, payload: Dict[str, Any]) -> None:
        envelope = self._build_envelope(message_type, payload)
        self.network.broadcast(envelope)

    def discover(self) -> None:
        self._broadcast(
            DISCOVER,
            {
                "capability": self.capability,
            },
        )

    def heartbeat(self) -> None:
        self._broadcast(
            HEARTBEAT,
            {
                "capability": self.capability,
            },
        )

    def cleanup_peers(self, ttl_seconds: float = 10.0) -> None:
        now = time.time()
        stale = [peer_id for peer_id, last_seen in self.peers.items() if now - last_seen > ttl_seconds]
        for peer_id in stale:
            self.peers.pop(peer_id, None)

    def offer_task(self, task_id: str, mission: str, budget_ceiling: float, constraints: Optional[Dict[str, Any]] = None) -> None:
        payload = {
            "task_id": task_id,
            "mission": mission,
            "budget_ceiling": budget_ceiling,
            "constraints": constraints or {},
        }
        self.offers[task_id] = payload
        self._broadcast(TASK_OFFER, payload)

    def _maybe_bid(self, offer: Dict[str, Any]) -> None:
        if self.is_planner:
            return
        bid_payload = {
            "task_id": offer["task_id"],
            "agent_id": self.agent_id,
            "price": float(self.bid_profile.get("price", 1.0)),
            "eta_ms": int(self.bid_profile.get("eta_ms", 100)),
            "capacity": int(self.bid_profile.get("capacity", 1)),
        }
        self._broadcast(BID, bid_payload)

    def emit_commit_vote(self, task_id: str) -> None:
        bids = self.bids_by_task.get(task_id, [])
        winner_bid = select_winner(bids)
        digest_source = f"{task_id}|{winner_bid['agent_id']}|{winner_bid['price']}|{winner_bid['eta_ms']}"
        digest = hashlib.sha256(digest_source.encode("utf-8")).hexdigest()
        self._broadcast(
            COMMIT_VOTE,
            {
                "task_id": task_id,
                "voter": self.agent_id,
                "winner": winner_bid["agent_id"],
                "digest": digest,
            },
        )

    def resolve_commit(self, task_id: str, total_nodes: int) -> Optional[str]:
        votes = self.votes_by_task.get(task_id, [])
        winner = resolve_commit(votes=votes, total_nodes=total_nodes)
        if winner:
            self.committed_winner_by_task[task_id] = winner
        return winner

    def execute_committed_task(self, task_id: str) -> Optional[Dict[str, Any]]:
        winner = self.committed_winner_by_task.get(task_id)
        if winner != self.agent_id:
            return None
        offer = self.offers.get(task_id)
        if offer is None:
            return None
        self._broadcast(
            EXEC_START,
            {
                "task_id": task_id,
                "worker_id": self.agent_id,
            },
        )
        result = execute_task(task=offer, worker_id=self.agent_id)
        self.executions[task_id] = result
        self._broadcast(
            EXEC_DONE,
            {
                "task_id": task_id,
                "worker_id": self.agent_id,
                "result_digest": result["result_digest"],
            },
        )
        return result

    def emit_verify_ack(self, task_id: str, event_hash: str) -> None:
        self._broadcast(
            VERIFY_ACK,
            {
                "task_id": task_id,
                "agent_id": self.agent_id,
                "event_hash": event_hash,
            },
        )

    def gossip_threat(self, threat_id: str, details: str) -> None:
        """
        Hive Memory: Broadcast a threat to update the swarm's shared world view.
        """
        self.threat_ledger[threat_id] = details
        self._broadcast(
            THREAT_GOSSIP,
            {
                "threat_id": threat_id,
                "details": details,
                "reporter": self.agent_id,
            },
        )

    def receive(self, envelope: Dict[str, Any]) -> None:
        if not self.active:
            return
        message_type = str(envelope["type"])
        sender = str(envelope["sender"])
        ts = float(envelope["ts"])
        nonce = str(envelope["nonce"])
        payload = dict(envelope["payload"])
        signature = str(envelope["sig"])
        sender_secret = self.network.agent_secrets.get(sender)
        if sender_secret is None:
            return
        signed_portion = {
            "type": message_type,
            "sender": sender,
            "ts": ts,
            "nonce": nonce,
            "payload": payload,
        }
        if not verify_payload(sender_secret, signed_portion, signature):
            return
        replay_ok, _ = self.replay.check_and_mark(sender=sender, nonce=nonce, ts=ts)
        if not replay_ok:
            return
        if message_type in {DISCOVER, HEARTBEAT}:
            self.peers[sender] = time.time()
            return
        if message_type == TASK_OFFER:
            task_id = str(payload["task_id"])
            self.offers[task_id] = payload
            self._maybe_bid(payload)
            return
        if message_type == BID:
            task_id = str(payload["task_id"])
            bids = self.bids_by_task.setdefault(task_id, [])
            existing = {str(item["agent_id"]) for item in bids}
            if str(payload["agent_id"]) not in existing:
                bids.append(payload)
            return
        if message_type == COMMIT_VOTE:
            task_id = str(payload["task_id"])
            votes = self.votes_by_task.setdefault(task_id, [])
            existing = {str(item["voter"]) for item in votes}
            if str(payload["voter"]) not in existing:
                votes.append(payload)
            return
        if message_type == EXEC_DONE:
            task_id = str(payload["task_id"])
            self.executions[task_id] = payload
            return
        if message_type == VERIFY_ACK:
            task_id = str(payload["task_id"])
            acks = self.verify_acks_by_task.setdefault(task_id, {})
            acks[str(payload["agent_id"])] = signature
            return
        if message_type == THREAT_GOSSIP:
            # Hive Memory: Update local world view from peer gossip
            threat_id = str(payload["threat_id"])
            details = str(payload["details"])
            self.threat_ledger[threat_id] = details
            return


class SwarmNetwork:
    def __init__(self, fault_injector: Optional[FaultInjector] = None):
        self.nodes: Dict[str, AgentNode] = {}
        self.agent_secrets: Dict[str, str] = {}
        self.events: List[EventRecord] = []
        self.fault_injector = fault_injector or FaultInjector()

    def register(self, node: AgentNode) -> None:
        self.nodes[node.agent_id] = node
        self.agent_secrets[node.agent_id] = node.secret

    def active_node_ids(self) -> List[str]:
        return [node_id for node_id, node in self.nodes.items() if node.active and not self.fault_injector.is_node_dropped(node_id)]

    def drop_node(self, node_id: str) -> None:
        self.fault_injector.dropped_nodes.add(node_id)

    def broadcast(self, envelope: Dict[str, Any]) -> None:
        sender = str(envelope["sender"])
        if self.fault_injector.is_node_dropped(sender):
            return
        self.fault_injector.apply_delay(str(envelope["type"]))
        self.events.append(
            EventRecord(
                ts=float(envelope["ts"]),
                actor=sender,
                event_type=str(envelope["type"]),
                payload=dict(envelope["payload"]),
            )
        )
        for node_id, node in self.nodes.items():
            if self.fault_injector.is_node_dropped(node_id):
                continue
            node.receive(envelope)

