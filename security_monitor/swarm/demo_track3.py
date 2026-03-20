import argparse
import json
import os
import time
from typing import Any, Dict, List, Literal, Optional, Tuple, TypedDict, cast

from security_monitor.integration.ai_engine import AIRiskEngine
from security_monitor.integration.settlement import SettlementEngine
from security_monitor.integration.foxmq_adapter import FoxMQAdapter
from security_monitor.integration.wdk_settlement import WDKSettlementAdapter
from security_monitor.swarm.agent_node import AgentNode, SwarmNetwork
from security_monitor.swarm.fault_injector import FaultInjector
from security_monitor.swarm.messages import (
    BLOCK_EXEC,
    NANOPAYMENT,
    REPUTATION_PENALTY,
    SCAN_QUOTE,
    SCAN_RESULT,
    THREAT_CONFIRM,
    THREAT_REPORT,
)
from security_monitor.swarm.proof import build_hash_chain, build_proof
from security_monitor.swarm.security import sign_payload, verify_payload
from security_monitor.roles import ScoutAgent, GuardianAgent, VerifierAgent


class DemoSummary(TypedDict):
    task_id: str
    winner: str
    active_nodes: List[str]
    fault_mode: str
    event_count: int
    proof_hash: str
    signer_count: int
    event_log_path: str
    proof_path: str
    commit_log_path: str
    settlement_tx_hash: str
    nanopayment_tx_hash: str
    transport_backend: str
    checks: Dict[str, bool]


class AcceptanceSummary(TypedDict):
    scenarios: Dict[str, DemoSummary]
    criteria: Dict[str, bool]
    report_path: str


class WarmupSummary(TypedDict):
    proof_log_path: str
    state_snapshot_path: str
    heartbeat_window_seconds: int
    outage_seconds: int
    mirror_latency_ms: float
    transport_backend: str
    checks: Dict[str, bool]


class FoxSwarmNetwork(SwarmNetwork):
    """
    SwarmNetwork extended with FoxMQ integration for P2P simulation.
    """
    def __init__(
        self,
        fault_injector: FaultInjector = None,
        foxmq_backend: str = "mqtt",
        vertex_rs_bridge_cmd: Optional[str] = None,
        foxmq_mqtt_addr: Optional[str] = None,
    ):
        super().__init__(fault_injector)
        self.fox_mq = FoxMQAdapter(
            backend=foxmq_backend,
            bridge_cmd=vertex_rs_bridge_cmd,
            mqtt_addr=foxmq_mqtt_addr,
        )
        self.fox_mq.join_network("swarm-control")

    def broadcast(self, envelope: Dict[str, Any]) -> None:
        super().broadcast(envelope)
        # Simulate P2P broadcast
        self.fox_mq.publish("swarm-events", envelope)


def _create_agents(network: SwarmNetwork, worker_count: int = 2) -> Tuple[ScoutAgent, List[AgentNode]]:
    # Scout (Planner)
    scout = ScoutAgent(
        agent_id="agent-scout",
        capability="scout",
        secret="secret-scout",
        bid_profile={"price": 99.0, "eta_ms": 999, "capacity": 0},
        network=network,
        is_planner=True,
    )
    nodes = [scout]
    scout_b = ScoutAgent(
        agent_id="agent-scout-b",
        capability="scout",
        secret="secret-scout-b",
        bid_profile={"price": 98.0, "eta_ms": 998, "capacity": 0},
        network=network,
        is_planner=True,
    )
    nodes.append(scout_b)

    # Guardian (Worker)
    for i in range(worker_count):
        guardian = GuardianAgent(
            agent_id=f"agent-worker-{i}",
            capability="guardian",
            secret=f"secret-worker-{i}",
            bid_profile={"price": 5.0 + i * 0.5, "eta_ms": 200 - i * 5, "capacity": 1},
            network=network,
        )
        nodes.append(guardian)
    
    # Verifier (Observer/Validator)
    verifier = VerifierAgent(
        agent_id="agent-verifier",
        capability="verifier",
        secret="secret-verifier",
        bid_profile={"price": 0.0, "eta_ms": 0, "capacity": 0},
        network=network,
    )
    nodes.append(verifier)

    for node in nodes:
        network.register(node)
    return scout, nodes


def run_demo(
    output_dir: str,
    fault_mode: Literal["none", "delay", "drop"],
    worker_count: int = 2,
    foxmq_backend: str = "mqtt",
    vertex_rs_bridge_cmd: Optional[str] = None,
    foxmq_mqtt_addr: Optional[str] = None,
) -> DemoSummary:
    # Use FoxSwarmNetwork for P2P simulation
    injector = FaultInjector()
    if fault_mode == "delay":
        injector.delayed_messages_ms["BID"] = 80
    network = FoxSwarmNetwork(
        fault_injector=injector,
        foxmq_backend=foxmq_backend,
        vertex_rs_bridge_cmd=vertex_rs_bridge_cmd,
        foxmq_mqtt_addr=foxmq_mqtt_addr,
    )
    
    planner, nodes = _create_agents(network, worker_count)
    scout = cast(ScoutAgent, planner)
    scout_b = cast(ScoutAgent, next(node for node in nodes if node.agent_id == "agent-scout-b"))

    for node in nodes:
        node.discover()
    for node in nodes:
        node.heartbeat()
    for node in nodes:
        node.cleanup_peers(ttl_seconds=30.0)

    # Determine expected winner based on logic in _create_agents
    # Default winner is worker-0 (lowest price)
    expected_winner = "agent-worker-0"

    if fault_mode == "drop":
        # In drop mode, we drop the expected winner to test resilience
        # We must drop BEFORE offer_task so the node doesn't bid
        network.drop_node(expected_winner)
        # The next best is worker-1
        expected_winner = "agent-worker-1"
        if worker_count < 2:
            pass

    payment_engine = WDKSettlementAdapter()
    payment_engine._balances["agent-client"] = {"USDT": 5.0}
    protection_fee = 0.5
    scout._broadcast(
        SCAN_QUOTE,
        {
            "requester": "agent-client",
            "provider": "agent-scout",
            "scan_target": "0x1234567890abcdef1234567890abcdef12345678",
            "fee": protection_fee,
            "token": "USDT",
            "service": "pre_tx_scan",
        },
    )
    payment_result = payment_engine.transfer(
        from_address="agent-client",
        to_address="agent-scout",
        amount=protection_fee,
        token="USDT",
    )
    if not payment_result["success"]:
        raise RuntimeError(f"nanopayment failed: {payment_result}")
    scout._broadcast(
        NANOPAYMENT,
        {
            "from": "agent-client",
            "to": "agent-scout",
            "amount": protection_fee,
            "token": "USDT",
            "tx_hash": payment_result["tx_hash"],
        },
    )

    target_address = "0x1234567890abcdef1234567890abcdef12345678"
    analysis = scout.analyze_target(target_address, amount=100.0)
    scout._broadcast(
        SCAN_RESULT,
        {
            "requester": "agent-client",
            "provider": "agent-scout",
            "target": target_address,
            "safe": analysis["safe"],
            "risk": analysis["risk"],
            "reason": analysis["reason"],
        },
    )
    if not analysis["safe"]:
        raise RuntimeError(f"Scout rejected target: {analysis}")

    malicious_target = "0x6666666666666666666666666666666666666666"
    primary_threat = scout.analyze_target(malicious_target, amount=100.0)
    secondary_threat = scout_b.analyze_target(malicious_target, amount=100.0)
    dual_sentinel_confirmed = (not primary_threat["safe"]) and (not secondary_threat["safe"])
    block_executed = False
    penalty_triggered = False
    reputation_registry = {
        "agent-client": 100,
    }
    if dual_sentinel_confirmed:
        scout._broadcast(
            THREAT_REPORT,
            {
                "target": malicious_target,
                "reporter": scout.agent_id,
                "risk": primary_threat["risk"],
                "reason": primary_threat["reason"],
            },
        )
        scout_b._broadcast(
            THREAT_CONFIRM,
            {
                "target": malicious_target,
                "confirmer": scout_b.agent_id,
                "risk": secondary_threat["risk"],
                "reason": secondary_threat["reason"],
            },
        )
        block_executed = True
        scout._broadcast(
            BLOCK_EXEC,
            {
                "target": malicious_target,
                "required_confirmations": 2,
                "confirmations": [scout.agent_id, scout_b.agent_id],
                "action": "block_transaction",
            },
        )
        reputation_registry["agent-client"] = max(0, reputation_registry["agent-client"] - 25)
        penalty_triggered = True
        scout._broadcast(
            REPUTATION_PENALTY,
            {
                "offender": "agent-client",
                "delta": -25,
                "new_score": reputation_registry["agent-client"],
                "reason": "confirmed_malicious_target",
            },
        )

    scout.offer_task(
        task_id="task-001",
        mission=target_address,
        budget_ceiling=float(analysis["suggested_price"]) * 10,
        constraints={"latency_ms_max": 500},
    )

    for node_id in network.active_node_ids():
        network.nodes[node_id].emit_commit_vote("task-001")

    total_active = len(network.active_node_ids())
    winners = []
    for node_id in network.active_node_ids():
        winner = network.nodes[node_id].resolve_commit("task-001", total_nodes=total_active)
        winners.append(winner)
    unique_winners = {winner for winner in winners if winner}
    if len(unique_winners) != 1:
        # It's possible to have no winner if everyone dropped?
        # But here we expect resilience
        if fault_mode == "drop" and expected_winner == "agent-worker-1" and len(unique_winners) == 0:
             # Case where maybe consensus failed due to drop?
             pass
        else:
             raise RuntimeError(f"commit failed, inconsistent winners: {unique_winners}")
    
    if unique_winners:
        winner_id = unique_winners.pop()
        execution_result = network.nodes[winner_id].execute_committed_task("task-001")
    else:
        winner_id = "none"
        execution_result = None

    if execution_result is None:
        # If we expected a winner but got none, that's an error unless fault injection explains it
        if fault_mode != "drop":
             raise RuntimeError("execution was not completed by committed winner")
        settlement_result = {"status": "failed", "tx_hash": "none"}
    else:
        # Extract settlement info from execution result
        settlement_result = {
            "status": execution_result.get("status", "failed"),
            "tx_hash": execution_result.get("wdk_tx", "none")
        }

    detected_threat = "IP:192.168.1.666"
    network.nodes[winner_id].gossip_threat("threat-999", detected_threat)

    pre_verify_chain = build_hash_chain(network.events)
    pre_verify_hash = pre_verify_chain[-1]["chain_hash"] if pre_verify_chain else "GENESIS"
    for node_id in network.active_node_ids():
        network.nodes[node_id].emit_verify_ack("task-001", pre_verify_hash)

    signatures = planner.verify_acks_by_task.get("task-001", {})
    proof = build_proof(events=network.events, signatures=signatures)

    os.makedirs(output_dir, exist_ok=True)
    event_log_path = os.path.join(output_dir, "structured_event_log.json")
    proof_path = os.path.join(output_dir, "coordination_proof.json")
    commit_log_path = os.path.join(output_dir, "commit_log.json")
    events_data = [event.to_dict() for event in network.events]
    commit_events = [event for event in events_data if event["event_type"] == "COMMIT_VOTE"]
    exec_done_events = [event for event in events_data if event["event_type"] == "EXEC_DONE"]
    verify_events = [event for event in events_data if event["event_type"] == "VERIFY_ACK"]
    gossip_events = [event for event in events_data if event["event_type"] == "THREAT_GOSSIP"]
    with open(event_log_path, "w", encoding="utf-8") as f:
        json.dump(events_data, f, ensure_ascii=False, indent=2)
    with open(proof_path, "w", encoding="utf-8") as f:
        json.dump(proof, f, ensure_ascii=False, indent=2)
    with open(commit_log_path, "w", encoding="utf-8") as f:
        json.dump(commit_events, f, ensure_ascii=False, indent=2)

    # Check Hive Memory Consistency
    hive_memory_consistent = True
    for node_id in network.active_node_ids():
        ledger = network.nodes[node_id].threat_ledger
        if ledger.get("threat-999") != detected_threat:
            hive_memory_consistent = False
            break

    checks = {
        "single_winner": len(unique_winners | {winner_id}) == 1,
        "no_double_assignment": len(exec_done_events) == 1,
        "proof_chain_complete": int(proof["event_count"]) == len(proof["chain"]),
        "verify_ack_emitted": len(verify_events) >= (total_active - 1), # At least most nodes ack
        "resilience_maintained": winner_id == expected_winner,
        "hive_memory_consistent": hive_memory_consistent and len(gossip_events) >= 1,
        "settlement_success": settlement_result["status"] == "success",
        "economy_payment_success": bool(payment_result["success"]),
        "economy_service_settled": str(payment_result["tx_hash"]).startswith("0x"),
        "dual_sentinel_consensus": dual_sentinel_confirmed,
        "autonomous_block_triggered": block_executed,
        "autonomous_penalty_triggered": penalty_triggered and reputation_registry["agent-client"] == 75,
    }

    return {
        "task_id": "task-001",
        "winner": winner_id,
        "active_nodes": network.active_node_ids(),
        "fault_mode": fault_mode,
        "event_count": len(network.events),
        "proof_hash": proof["final_chain_hash"],
        "signer_count": len(signatures),
        "event_log_path": event_log_path,
        "proof_path": proof_path,
        "commit_log_path": commit_log_path,
        "settlement_tx_hash": settlement_result["tx_hash"],
        "nanopayment_tx_hash": payment_result["tx_hash"],
        "transport_backend": foxmq_backend,
        "checks": checks,
    }


def run_acceptance(
    output_dir: str,
    worker_count: int = 2,
    foxmq_backend: str = "mqtt",
    vertex_rs_bridge_cmd: Optional[str] = None,
    foxmq_mqtt_addr: Optional[str] = None,
) -> AcceptanceSummary:
    scenarios: Dict[str, DemoSummary] = {}
    for mode in ("none", "delay", "drop"):
        scenario_dir = os.path.join(output_dir, mode)
        scenarios[mode] = run_demo(
            output_dir=scenario_dir,
            fault_mode=cast(Literal["none", "delay", "drop"], mode),
            worker_count=worker_count,
            foxmq_backend=foxmq_backend,
            vertex_rs_bridge_cmd=vertex_rs_bridge_cmd,
            foxmq_mqtt_addr=foxmq_mqtt_addr,
        )
    criteria = {
        "coordination_correctness": all(
            scenario["checks"]["single_winner"] and scenario["checks"]["no_double_assignment"]
            for scenario in scenarios.values()
        ),
        "resilience": scenarios["delay"]["checks"]["resilience_maintained"] and scenarios["drop"]["checks"]["resilience_maintained"],
        "auditability": all(
            scenario["checks"]["proof_chain_complete"] and os.path.exists(scenario["proof_path"])
            for scenario in scenarios.values()
        ),
        "security_posture": all(scenario["checks"]["verify_ack_emitted"] for scenario in scenarios.values()),
        "hive_memory": all(scenario["checks"]["hive_memory_consistent"] for scenario in scenarios.values()),
        "settlement": all(scenario["checks"]["settlement_success"] for scenario in scenarios.values()),
        "agent_economy": all(
            scenario["checks"]["economy_payment_success"] and scenario["checks"]["economy_service_settled"]
            for scenario in scenarios.values()
        ),
        "autonomous_governance": all(
            scenario["checks"]["dual_sentinel_consensus"]
            and scenario["checks"]["autonomous_block_triggered"]
            and scenario["checks"]["autonomous_penalty_triggered"]
            for scenario in scenarios.values()
        ),
        "developer_clarity": all(
            os.path.exists(scenario["event_log_path"]) and os.path.exists(scenario["commit_log_path"])
            for scenario in scenarios.values()
        ),
    }
    report_path = os.path.join(output_dir, "acceptance_report.json")
    report: Dict[str, Any] = {
        "criteria": criteria,
        "scenarios": scenarios,
    }
    os.makedirs(output_dir, exist_ok=True)
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
    return {
        "scenarios": scenarios,
        "criteria": criteria,
        "report_path": report_path,
    }


def run_warmup(
    output_dir: str,
    heartbeat_window_seconds: int = 30,
    outage_seconds: int = 10,
    heartbeat_seconds: float = 1.0,
    stale_after_seconds: float = 3.0,
    foxmq_backend: str = "mqtt",
    vertex_rs_bridge_cmd: Optional[str] = None,
    foxmq_mqtt_addr: Optional[str] = None,
) -> WarmupSummary:
    if foxmq_backend == "simulated":
        FoxMQAdapter.reset_simulation()
    channel = f"warmup-{int(time.time() * 1000)}"
    logs: List[str] = []
    nonce_counter = {"agent-a": 0, "agent-b": 0}
    hello_ack_seen = {"agent-a": False, "agent-b": False}
    stale_detected = False
    heartbeat_rx_count = 0

    nodes: Dict[str, Dict[str, Any]] = {
        "agent-a": {
            "secret": "secret-agent-a",
            "online": True,
            "state": {
                "peer_id": "agent-a",
                "last_seen_ms": int(time.time() * 1000),
                "role": "carrier",
                "status": "ready",
            },
            "peers": {},
        },
        "agent-b": {
            "secret": "secret-agent-b",
            "online": True,
            "state": {
                "peer_id": "agent-b",
                "last_seen_ms": int(time.time() * 1000),
                "role": "carrier",
                "status": "ready",
            },
            "peers": {},
        },
    }

    adapters = {
        "agent-a": FoxMQAdapter(
            node_id="agent-a",
            backend=foxmq_backend,
            bridge_cmd=vertex_rs_bridge_cmd,
            mqtt_addr=foxmq_mqtt_addr,
        ),
        "agent-b": FoxMQAdapter(
            node_id="agent-b",
            backend=foxmq_backend,
            bridge_cmd=vertex_rs_bridge_cmd,
            mqtt_addr=foxmq_mqtt_addr,
        ),
    }

    for adapter in adapters.values():
        adapter.join_network(channel)

    def _log(event: str, actor: str, detail: Dict[str, Any]) -> None:
        line = json.dumps(
            {
                "ts_ms": int(time.time() * 1000),
                "event": event,
                "actor": actor,
                "detail": detail,
            },
            ensure_ascii=False,
        )
        logs.append(line)
        print(line, flush=True)

    def _mark_stale() -> None:
        nonlocal stale_detected
        now_ms = int(time.time() * 1000)
        stale_ms = int(stale_after_seconds * 1000)
        for node_id, node_data in nodes.items():
            peers = node_data["peers"]
            for peer_id, peer_state in peers.items():
                if now_ms - int(peer_state["last_seen_ms"]) > stale_ms and peer_state["status"] != "stale":
                    peer_state["status"] = "stale"
                    _log("PEER_STALE", node_id, {"peer_id": peer_id})
                    if node_id == "agent-a" and peer_id == "agent-b":
                        stale_detected = True

    def _send(sender: str, message_type: str, payload: Dict[str, Any]) -> None:
        nonce_counter[sender] += 1
        envelope: Dict[str, Any] = {
            "type": message_type,
            "sender": sender,
            "ts": time.time(),
            "nonce": f"{sender}-{nonce_counter[sender]}",
            "payload": payload,
        }
        signed_portion = {
            "type": envelope["type"],
            "sender": envelope["sender"],
            "ts": envelope["ts"],
            "nonce": envelope["nonce"],
            "payload": envelope["payload"],
        }
        envelope["sig"] = sign_payload(nodes[sender]["secret"], signed_portion)
        _log(f"{message_type}_TX", sender, payload)
        adapters[sender].publish(channel, envelope)

    def _on_message(receiver: str, envelope: Dict[str, Any]) -> None:
        nonlocal heartbeat_rx_count
        if not nodes[receiver]["online"]:
            return
        sender = str(envelope.get("sender", ""))
        if sender == receiver:
            return
        if sender not in nodes:
            return
        signed_portion = {
            "type": envelope["type"],
            "sender": envelope["sender"],
            "ts": envelope["ts"],
            "nonce": envelope["nonce"],
            "payload": envelope["payload"],
        }
        if not verify_payload(nodes[sender]["secret"], signed_portion, str(envelope.get("sig", ""))):
            _log("SIG_REJECTED", receiver, {"sender": sender, "type": envelope.get("type")})
            return
        payload = dict(envelope["payload"])
        message_type = str(envelope["type"])
        peer_state = nodes[receiver]["peers"].setdefault(
            sender,
            {"peer_id": sender, "last_seen_ms": 0, "role": "unknown", "status": "unknown"},
        )
        peer_state["last_seen_ms"] = int(time.time() * 1000)
        if "role" in payload:
            peer_state["role"] = str(payload["role"])
        if "status" in payload:
            peer_state["status"] = str(payload["status"])
        _log(f"{message_type}_RX", receiver, {"sender": sender, **payload})
        if message_type == "HELLO":
            _send(
                receiver,
                "HELLO_ACK",
                {
                    "peer_id": receiver,
                    "last_seen_ms": int(time.time() * 1000),
                    "role": str(nodes[receiver]["state"]["role"]),
                    "status": str(nodes[receiver]["state"]["status"]),
                },
            )
        if message_type == "HELLO_ACK":
            hello_ack_seen[receiver] = True
        if message_type == "HEARTBEAT":
            heartbeat_rx_count += 1

    adapters["agent-a"].subscribe(channel, lambda envelope: _on_message("agent-a", envelope))
    adapters["agent-b"].subscribe(channel, lambda envelope: _on_message("agent-b", envelope))

    _send("agent-a", "DISCOVER", {"peer_id": "agent-a"})
    _send("agent-b", "DISCOVER", {"peer_id": "agent-b"})
    _send(
        "agent-a",
        "HELLO",
        {
            "peer_id": "agent-a",
            "last_seen_ms": int(time.time() * 1000),
            "role": "carrier",
            "status": "ready",
        },
    )
    _send(
        "agent-b",
        "HELLO",
        {
            "peer_id": "agent-b",
            "last_seen_ms": int(time.time() * 1000),
            "role": "carrier",
            "status": "ready",
        },
    )

    start = time.time()
    while time.time() - start < heartbeat_window_seconds:
        for node_id, node_data in nodes.items():
            if not node_data["online"]:
                continue
            node_data["state"]["last_seen_ms"] = int(time.time() * 1000)
            _send(
                node_id,
                "HEARTBEAT",
                {
                    "peer_id": node_id,
                    "last_seen_ms": int(node_data["state"]["last_seen_ms"]),
                    "role": str(node_data["state"]["role"]),
                    "status": str(node_data["state"]["status"]),
                },
            )
        _mark_stale()
        time.sleep(heartbeat_seconds)

    mirror_latency_ms = 10000.0
    nodes["agent-a"]["state"]["role"] = "scout"
    change_start = time.perf_counter()
    _send(
        "agent-a",
        "STATE_SYNC",
        {
            "peer_id": "agent-a",
            "last_seen_ms": int(time.time() * 1000),
            "role": "scout",
            "status": str(nodes["agent-a"]["state"]["status"]),
        },
    )
    wait_deadline = time.perf_counter() + 1.0
    while time.perf_counter() < wait_deadline:
        mirrored = nodes["agent-b"]["peers"].get("agent-a", {}).get("role") == "scout"
        if mirrored:
            mirror_latency_ms = (time.perf_counter() - change_start) * 1000.0
            break
        time.sleep(0.01)
    _log("ROLE_TOGGLE", "agent-a", {"new_role": "scout", "mirror_latency_ms": mirror_latency_ms})

    nodes["agent-b"]["online"] = False
    _log("NODE_OFFLINE", "agent-b", {"duration_seconds": outage_seconds})
    outage_start = time.time()
    while time.time() - outage_start < outage_seconds:
        nodes["agent-a"]["state"]["last_seen_ms"] = int(time.time() * 1000)
        _send(
            "agent-a",
            "HEARTBEAT",
            {
                "peer_id": "agent-a",
                "last_seen_ms": int(nodes["agent-a"]["state"]["last_seen_ms"]),
                "role": str(nodes["agent-a"]["state"]["role"]),
                "status": str(nodes["agent-a"]["state"]["status"]),
            },
        )
        _mark_stale()
        time.sleep(heartbeat_seconds)

    nodes["agent-b"]["online"] = True
    nodes["agent-b"]["state"]["status"] = "ready"
    _log("NODE_ONLINE", "agent-b", {"status": "ready"})
    _send("agent-b", "DISCOVER", {"peer_id": "agent-b"})
    _send(
        "agent-b",
        "HELLO",
        {
            "peer_id": "agent-b",
            "last_seen_ms": int(time.time() * 1000),
            "role": str(nodes["agent-b"]["state"]["role"]),
            "status": str(nodes["agent-b"]["state"]["status"]),
        },
    )
    recovery_deadline = time.time() + max(1.0, 3 * heartbeat_seconds)
    while time.time() < recovery_deadline:
        for node_id, node_data in nodes.items():
            if not node_data["online"]:
                continue
            node_data["state"]["last_seen_ms"] = int(time.time() * 1000)
            _send(
                node_id,
                "HEARTBEAT",
                {
                    "peer_id": node_id,
                    "last_seen_ms": int(node_data["state"]["last_seen_ms"]),
                    "role": str(node_data["state"]["role"]),
                    "status": str(node_data["state"]["status"]),
                },
            )
        _mark_stale()
        time.sleep(heartbeat_seconds)

    for adapter in adapters.values():
        adapter.leave_network()

    os.makedirs(output_dir, exist_ok=True)
    proof_log_path = os.path.join(output_dir, "warmup_terminal_log.jsonl")
    state_snapshot_path = os.path.join(output_dir, "warmup_state_snapshot.json")
    with open(proof_log_path, "w", encoding="utf-8") as f:
        f.write("\n".join(logs))
    snapshot = {
        node_id: {
            "self": node_data["state"],
            "peers": node_data["peers"],
        }
        for node_id, node_data in nodes.items()
    }
    with open(state_snapshot_path, "w", encoding="utf-8") as f:
        json.dump(snapshot, f, ensure_ascii=False, indent=2)

    discovery_ok = "agent-b" in nodes["agent-a"]["peers"] and "agent-a" in nodes["agent-b"]["peers"]
    state_sync_ok = mirror_latency_ms < 1000.0 and nodes["agent-b"]["peers"].get("agent-a", {}).get("role") == "scout"
    recovered_ok = nodes["agent-a"]["peers"].get("agent-b", {}).get("status") != "stale"
    checks = {
        "discovery": discovery_ok,
        "handshake": hello_ack_seen["agent-a"] and hello_ack_seen["agent-b"],
        "heartbeats": heartbeat_rx_count >= 6,
        "state_sync_under_1s": state_sync_ok,
        "stale_detection": stale_detected,
        "recovery": recovered_ok,
    }
    return {
        "proof_log_path": proof_log_path,
        "state_snapshot_path": state_snapshot_path,
        "heartbeat_window_seconds": heartbeat_window_seconds,
        "outage_seconds": outage_seconds,
        "mirror_latency_ms": round(mirror_latency_ms, 3),
        "transport_backend": foxmq_backend,
        "checks": checks,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Track3 leaderless swarm demo")
    parser.add_argument(
        "--mode",
        choices=["single", "acceptance", "warmup"],
        default="single",
        help="single: run one scenario, acceptance: run none/delay/drop, warmup: run handshake/state-sync/failure proof",
    )
    parser.add_argument(
        "--output-dir",
        default=os.path.join(os.getcwd(), "artifacts"),
        help="Directory for structured logs and proof files",
    )
    parser.add_argument(
        "--fault",
        choices=["none", "delay", "drop"],
        default="delay",
        help="Fault mode to inject during demo",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=2,
        help="Number of worker agents (default: 2)",
    )
    parser.add_argument(
        "--warmup-window-seconds",
        type=int,
        default=30,
        help="Heartbeat proof window for warmup mode",
    )
    parser.add_argument(
        "--warmup-outage-seconds",
        type=int,
        default=10,
        help="Node outage duration for warmup mode",
    )
    parser.add_argument(
        "--heartbeat-seconds",
        type=float,
        default=1.0,
        help="Heartbeat interval for warmup mode",
    )
    parser.add_argument(
        "--stale-after-seconds",
        type=float,
        default=3.0,
        help="Mark peer stale after this timeout in warmup mode",
    )
    parser.add_argument(
        "--foxmq-backend",
        choices=["simulated", "official", "mqtt"],
        default=os.getenv("FOXMQ_BACKEND", "mqtt"),
        help="FoxMQ transport backend",
    )
    parser.add_argument(
        "--vertex-rs-bridge-cmd",
        default=os.getenv("VERTEX_RS_BRIDGE_CMD", ""),
        help="Rust bridge command used by official backend, example: vertex-rs-bridge --host 127.0.0.1 --port 1883 --stdio",
    )
    parser.add_argument(
        "--foxmq-mqtt-addr",
        default=os.getenv("FOXMQ_MQTT_ADDR", "127.0.0.1:1883"),
        help="MQTT broker address used by mqtt backend, format host:port",
    )
    args = parser.parse_args()

    if args.mode == "warmup":
        warmup = run_warmup(
            output_dir=args.output_dir,
            heartbeat_window_seconds=args.warmup_window_seconds,
            outage_seconds=args.warmup_outage_seconds,
            heartbeat_seconds=args.heartbeat_seconds,
            stale_after_seconds=args.stale_after_seconds,
            foxmq_backend=args.foxmq_backend,
            vertex_rs_bridge_cmd=args.vertex_rs_bridge_cmd or None,
            foxmq_mqtt_addr=args.foxmq_mqtt_addr or None,
        )
        print("\nTRACK3 WARMUP SUMMARY")
        print(f"Proof Log:    {warmup['proof_log_path']}")
        print(f"State File:   {warmup['state_snapshot_path']}")
        print(f"Mirror Latency(ms): {warmup['mirror_latency_ms']}")
        print(f"Transport:    {warmup['transport_backend']}")
        print(f"Checks:       {warmup['checks']}")
        return 0

    if args.mode == "acceptance":
        acceptance = run_acceptance(
            output_dir=args.output_dir,
            worker_count=args.workers,
            foxmq_backend=args.foxmq_backend,
            vertex_rs_bridge_cmd=args.vertex_rs_bridge_cmd or None,
            foxmq_mqtt_addr=args.foxmq_mqtt_addr or None,
        )
        print("\nTRACK3 ACCEPTANCE SUMMARY")
        print(f"Report: {acceptance['report_path']}")
        print(f"Transport: {args.foxmq_backend}")
        for name, passed in acceptance["criteria"].items():
            print(f"{name}: {'PASS' if passed else 'FAIL'}")
        return 0

    selected_fault = cast(Literal["none", "delay", "drop"], args.fault)
    summary = run_demo(
        output_dir=args.output_dir,
        fault_mode=selected_fault,
        worker_count=args.workers,
        foxmq_backend=args.foxmq_backend,
        vertex_rs_bridge_cmd=args.vertex_rs_bridge_cmd or None,
        foxmq_mqtt_addr=args.foxmq_mqtt_addr or None,
    )
    print("\nTRACK3 DEMO SUMMARY")
    print(f"Task ID:      {summary['task_id']}")
    print(f"Winner:       {summary['winner']}")
    print(f"Fault Mode:   {summary['fault_mode']}")
    print(f"Active Nodes: {', '.join(summary['active_nodes'])}")
    print(f"Events:       {summary['event_count']}")
    print(f"Proof Hash:   {summary['proof_hash']}")
    print(f"Signers:      {summary['signer_count']}")
    print(f"Event Log:    {summary['event_log_path']}")
    print(f"Commit Log:   {summary['commit_log_path']}")
    print(f"Proof File:   {summary['proof_path']}")
    print(f"Settlement:   {summary['settlement_tx_hash']}")
    print(f"Transport:    {summary['transport_backend']}")
    print(f"Checks:       {summary['checks']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
