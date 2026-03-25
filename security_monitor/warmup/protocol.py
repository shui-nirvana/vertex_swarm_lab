import json
import os
import time
from typing import Any, Dict, List, Optional, TypedDict

from security_monitor.integration.foxmq_adapter import FoxMQAdapter
from security_monitor.swarm.security import sign_payload, verify_payload


class WarmupSummary(TypedDict):
    proof_log_path: str
    state_snapshot_path: str
    heartbeat_window_seconds: int
    outage_seconds: int
    mirror_latency_ms: float
    transport_backend: str
    checks: Dict[str, bool]


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
