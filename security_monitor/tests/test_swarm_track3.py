import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from concurrent.futures import ThreadPoolExecutor, as_completed
from unittest import mock

from security_monitor.integration.foxmq_adapter import FoxMQAdapter
from security_monitor.swarm.demo_track3 import _create_agents, run_acceptance, run_demo, run_warmup
from security_monitor.swarm.messages import DISCOVER
from security_monitor.swarm.negotiation import select_winner
from security_monitor.swarm.security import verify_payload
from security_monitor.swarm.agent_node import SwarmNetwork

_OFFICIAL_E2E_BRIDGE_CMD = os.getenv("VERTEX_RS_BRIDGE_CMD", "").strip()
_OFFICIAL_E2E_ENABLED = os.getenv("OFFICIAL_E2E", "0") == "1" and bool(_OFFICIAL_E2E_BRIDGE_CMD)
_OFFICIAL_MULTI_E2E_TEMPLATE = os.getenv("VERTEX_RS_BRIDGE_CMD_TEMPLATE", "").strip()
_OFFICIAL_MULTI_E2E_ENABLED = os.getenv("OFFICIAL_MULTI_E2E", "0") == "1" and bool(_OFFICIAL_MULTI_E2E_TEMPLATE)
_MQTT_E2E_ADDR = os.getenv("FOXMQ_MQTT_ADDR", "").strip()
_MQTT_E2E_ENABLED = os.getenv("MQTT_E2E", "0") == "1" and bool(_MQTT_E2E_ADDR)


class Track3SwarmTests(unittest.TestCase):
    def test_full_loop_without_fault(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            summary = run_demo(output_dir=tmp, fault_mode="none", foxmq_backend="simulated")
            self.assertEqual(summary["winner"], "agent-worker-0")
            self.assertEqual(summary["signer_count"], len(summary["active_nodes"]))
            self.assertGreater(summary["event_count"], 0)
            self.assertTrue(os.path.exists(summary["event_log_path"]))
            self.assertTrue(os.path.exists(summary["proof_path"]))
            self.assertTrue(summary["nanopayment_tx_hash"].startswith("0x"))
            self.assertTrue(summary["checks"]["economy_payment_success"])
            self.assertTrue(summary["checks"]["dual_sentinel_consensus"])
            self.assertTrue(summary["checks"]["autonomous_penalty_triggered"])

    def test_loop_with_node_drop(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            summary = run_demo(output_dir=tmp, fault_mode="drop", foxmq_backend="simulated")
            self.assertEqual(summary["winner"], "agent-worker-1")
            self.assertEqual(summary["signer_count"], len(summary["active_nodes"]))

    def test_proof_has_hash_chain(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            summary = run_demo(output_dir=tmp, fault_mode="delay", foxmq_backend="simulated")
            with open(summary["proof_path"], "r", encoding="utf-8") as f:
                proof = json.load(f)
            self.assertIn("final_chain_hash", proof)
            self.assertIn("chain", proof)
            self.assertEqual(proof["event_count"], len(proof["chain"]))
            if proof["chain"]:
                self.assertEqual(proof["final_chain_hash"], proof["chain"][-1]["chain_hash"])

    def test_deterministic_winner_tie_break_by_agent_id(self) -> None:
        bids = [
            {"agent_id": "agent-z", "price": 5.0, "eta_ms": 100},
            {"agent_id": "agent-a", "price": 5.0, "eta_ms": 100},
            {"agent_id": "agent-m", "price": 5.0, "eta_ms": 100},
        ]
        winner = select_winner(bids)
        self.assertEqual(winner["agent_id"], "agent-a")

    def test_replay_message_is_rejected(self) -> None:
        network = SwarmNetwork()
        planner, nodes = _create_agents(network)
        worker = [node for node in nodes if node.agent_id == "agent-worker-0"][0]
        envelope = worker._build_envelope(DISCOVER, {"capability": "worker"})
        signed_portion = {
            "type": envelope["type"],
            "sender": envelope["sender"],
            "ts": envelope["ts"],
            "nonce": envelope["nonce"],
            "payload": envelope["payload"],
        }
        self.assertTrue(verify_payload(worker.secret, signed_portion, envelope["sig"]))
        network.broadcast(envelope)
        first_seen = planner.peers.get(worker.agent_id)
        self.assertIsNotNone(first_seen)
        network.broadcast(envelope)
        second_seen = planner.peers.get(worker.agent_id)
        self.assertEqual(first_seen, second_seen)

    def test_no_double_assignment_in_event_log(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            summary = run_demo(output_dir=tmp, fault_mode="none", foxmq_backend="simulated")
            with open(summary["event_log_path"], "r", encoding="utf-8") as f:
                events = json.load(f)
            exec_done = [event for event in events if event["event_type"] == "EXEC_DONE"]
            self.assertEqual(len(exec_done), 1)

    def test_acceptance_bundle_exports_report(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            acceptance = run_acceptance(output_dir=tmp, foxmq_backend="simulated")
            self.assertTrue(os.path.exists(acceptance["report_path"]))
            self.assertTrue(all(acceptance["criteria"].values()))

    def test_hive_memory_gossip_recorded(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            summary = run_demo(output_dir=tmp, fault_mode="none", foxmq_backend="simulated")
            self.assertTrue(summary["checks"]["hive_memory_consistent"])
            with open(summary["event_log_path"], "r", encoding="utf-8") as f:
                events = json.load(f)
            gossip_events = [event for event in events if event["event_type"] == "THREAT_GOSSIP"]
            self.assertGreaterEqual(len(gossip_events), 1)

    def test_agent_economy_and_dual_sentinel_events_recorded(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            summary = run_demo(output_dir=tmp, fault_mode="none", foxmq_backend="simulated")
            with open(summary["event_log_path"], "r", encoding="utf-8") as f:
                events = json.load(f)
            event_types = {event["event_type"] for event in events}
            self.assertIn("SCAN_QUOTE", event_types)
            self.assertIn("NANOPAYMENT", event_types)
            self.assertIn("THREAT_REPORT", event_types)
            self.assertIn("THREAT_CONFIRM", event_types)
            self.assertIn("BLOCK_EXEC", event_types)
            self.assertIn("REPUTATION_PENALTY", event_types)

    def test_warmup_proof_flow(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            summary = run_warmup(
                output_dir=tmp,
                heartbeat_window_seconds=2,
                outage_seconds=1,
                heartbeat_seconds=0.1,
                stale_after_seconds=0.25,
                foxmq_backend="simulated",
            )
            self.assertTrue(os.path.exists(summary["proof_log_path"]))
            self.assertTrue(os.path.exists(summary["state_snapshot_path"]))
            self.assertTrue(all(summary["checks"].values()))
            self.assertLess(summary["mirror_latency_ms"], 1000.0)
            self.assertEqual(summary["transport_backend"], "simulated")

    def test_demo_transport_backend_field(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            summary = run_demo(output_dir=tmp, fault_mode="none", foxmq_backend="simulated")
            self.assertEqual(summary["transport_backend"], "simulated")

    def test_official_backend_uses_vertex_rs_bridge_when_configured(self) -> None:
        sentinel_client = object()
        with mock.patch("security_monitor.integration.foxmq_adapter._VertexRsBridgeClient", return_value=sentinel_client):
            with mock.patch(
                "security_monitor.integration.foxmq_adapter.os.getenv",
                side_effect=lambda k, d=None: "vertex-rs-bridge --stdio" if k == "VERTEX_RS_BRIDGE_CMD" else d,
            ):
                adapter = FoxMQAdapter(node_id="n1", backend="official")
        self.assertIs(adapter._official_client, sentinel_client)
        self.assertIn("vertex-rs:", str(adapter.backend_info()["module"]))

    def test_official_backend_prefers_explicit_bridge_cmd_over_env(self) -> None:
        sentinel_client = object()
        with mock.patch("security_monitor.integration.foxmq_adapter._VertexRsBridgeClient", return_value=sentinel_client) as patched:
            with mock.patch("security_monitor.integration.foxmq_adapter.os.getenv", return_value=""):
                adapter = FoxMQAdapter(
                    node_id="n1",
                    backend="official",
                    bridge_cmd="vertex-rs-bridge --host 127.0.0.1 --port 1883 --stdio",
                )
        self.assertIs(adapter._official_client, sentinel_client)
        patched.assert_called_once_with(
            bridge_cmd="vertex-rs-bridge --host 127.0.0.1 --port 1883 --stdio",
            node_id="n1",
        )

    def test_official_backend_without_sdk_or_bridge_raises(self) -> None:
        with mock.patch("security_monitor.integration.foxmq_adapter.os.getenv", return_value=""):
            with self.assertRaises(RuntimeError):
                FoxMQAdapter(node_id="n1", backend="official")

    def test_official_backend_bridge_executable_missing_has_actionable_error(self) -> None:
        missing_cmd = "definitely-missing-vertex-rs-bridge-exe --stdio"
        with self.assertRaises(RuntimeError) as ctx:
            FoxMQAdapter(node_id="n1", backend="official", bridge_cmd=missing_cmd)
        self.assertIn("executable not found", str(ctx.exception))
        self.assertIn("VERTEX_RS_BRIDGE_CMD", str(ctx.exception))

    def test_official_backend_wraps_bridge_process_start_failure(self) -> None:
        with mock.patch("security_monitor.integration.foxmq_adapter.shutil.which", return_value="C:\\fake\\vertex-rs-bridge.exe"):
            with mock.patch(
                "security_monitor.integration.foxmq_adapter.subprocess.Popen",
                side_effect=FileNotFoundError("missing dependency"),
            ):
                with self.assertRaises(RuntimeError) as ctx:
                    FoxMQAdapter(node_id="n1", backend="official", bridge_cmd="vertex-rs-bridge --stdio")
        self.assertIn("failed to start vertex-rs bridge command", str(ctx.exception))

    def test_mqtt_backend_prefers_explicit_addr_over_env(self) -> None:
        sentinel_client = object()
        with mock.patch("security_monitor.integration.foxmq_adapter._FoxMqttClient", return_value=sentinel_client) as patched:
            with mock.patch(
                "security_monitor.integration.foxmq_adapter.os.getenv",
                side_effect=lambda k, d=None: "10.0.0.1:1883" if k == "FOXMQ_MQTT_ADDR" else d,
            ):
                adapter = FoxMQAdapter(node_id="n1", backend="mqtt", mqtt_addr="127.0.0.1:1884")
        self.assertIs(adapter._official_client, sentinel_client)
        patched.assert_called_once_with(mqtt_addr="127.0.0.1:1884", node_id="n1")
        self.assertEqual(adapter.backend_info()["module"], "mqtt:127.0.0.1:1884")

    def test_mqtt_backend_uses_env_when_addr_not_provided(self) -> None:
        sentinel_client = object()
        with mock.patch("security_monitor.integration.foxmq_adapter._FoxMqttClient", return_value=sentinel_client) as patched:
            with mock.patch(
                "security_monitor.integration.foxmq_adapter.os.getenv",
                side_effect=lambda k, d=None: "127.0.0.1:1885" if k == "FOXMQ_MQTT_ADDR" else d,
            ):
                adapter = FoxMQAdapter(node_id="n2", backend="mqtt")
        self.assertIs(adapter._official_client, sentinel_client)
        patched.assert_called_once_with(mqtt_addr="127.0.0.1:1885", node_id="n2")
        self.assertEqual(adapter.backend_info()["module"], "mqtt:127.0.0.1:1885")

    def test_default_backend_is_mqtt(self) -> None:
        sentinel_client = object()
        with mock.patch("security_monitor.integration.foxmq_adapter._FoxMqttClient", return_value=sentinel_client) as patched:
            with mock.patch(
                "security_monitor.integration.foxmq_adapter.os.getenv",
                side_effect=lambda k, d=None: "127.0.0.1:1886" if k == "FOXMQ_MQTT_ADDR" else d,
            ):
                adapter = FoxMQAdapter(node_id="n3")
        self.assertEqual(adapter.backend, "mqtt")
        self.assertIs(adapter._official_client, sentinel_client)
        patched.assert_called_once_with(mqtt_addr="127.0.0.1:1886", node_id="n3")

    @unittest.skipUnless(_MQTT_E2E_ENABLED, "set MQTT_E2E=1 and FOXMQ_MQTT_ADDR to run mqtt transport e2e")
    def test_mqtt_transport_demo_e2e(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            summary = run_demo(
                output_dir=tmp,
                fault_mode="none",
                worker_count=3,
                foxmq_backend="mqtt",
                foxmq_mqtt_addr=_MQTT_E2E_ADDR,
            )
            self.assertEqual(summary["transport_backend"], "mqtt")
            self.assertTrue(summary["checks"]["single_winner"])
            self.assertTrue(summary["checks"]["no_double_assignment"])

    @unittest.skipUnless(_OFFICIAL_E2E_ENABLED, "set OFFICIAL_E2E=1 and VERTEX_RS_BRIDGE_CMD to run official transport e2e")
    def test_official_transport_demo_e2e(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            summary = run_demo(
                output_dir=tmp,
                fault_mode="none",
                worker_count=3,
                foxmq_backend="official",
                vertex_rs_bridge_cmd=_OFFICIAL_E2E_BRIDGE_CMD,
            )
            self.assertEqual(summary["transport_backend"], "official")
            self.assertTrue(summary["checks"]["single_winner"])
            self.assertTrue(summary["checks"]["no_double_assignment"])
            self.assertTrue(summary["checks"]["proof_chain_complete"])

    @unittest.skipUnless(_OFFICIAL_E2E_ENABLED, "set OFFICIAL_E2E=1 and VERTEX_RS_BRIDGE_CMD to run official transport e2e")
    def test_official_transport_warmup_e2e(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            summary = run_warmup(
                output_dir=tmp,
                heartbeat_window_seconds=2,
                outage_seconds=1,
                heartbeat_seconds=0.1,
                stale_after_seconds=0.25,
                foxmq_backend="official",
                vertex_rs_bridge_cmd=_OFFICIAL_E2E_BRIDGE_CMD,
            )
            self.assertEqual(summary["transport_backend"], "official")
            self.assertIn("discovery", summary["checks"])
            self.assertIn("handshake", summary["checks"])

    @unittest.skipUnless(
        _OFFICIAL_MULTI_E2E_ENABLED,
        "set OFFICIAL_MULTI_E2E=1 and VERTEX_RS_BRIDGE_CMD_TEMPLATE to run multi-port official transport e2e",
    )
    def test_official_transport_multi_port_loopback_e2e(self) -> None:
        ports = [1883, 1884, 1885]
        with tempfile.TemporaryDirectory() as tmp:
            def _run_port(port: int) -> dict:
                bridge_cmd = _OFFICIAL_MULTI_E2E_TEMPLATE.format(host="127.0.0.1", port=port)
                output_dir = os.path.join(tmp, f"node-{port}")
                command = [
                    sys.executable,
                    "-m",
                    "security_monitor.swarm.demo_track3",
                    "--mode",
                    "single",
                    "--workers",
                    "2",
                    "--fault",
                    "none",
                    "--foxmq-backend",
                    "official",
                    "--vertex-rs-bridge-cmd",
                    bridge_cmd,
                    "--output-dir",
                    output_dir,
                ]
                start = time.perf_counter()
                completed = subprocess.run(command, capture_output=True, text=True, timeout=180)
                proof_path = os.path.join(output_dir, "coordination_proof.json")
                proof_event_count = -1
                if os.path.exists(proof_path):
                    with open(proof_path, "r", encoding="utf-8") as f:
                        proof = json.load(f)
                    proof_event_count = int(proof.get("event_count", -1))
                return {
                    "port": port,
                    "returncode": completed.returncode,
                    "stdout": completed.stdout,
                    "stderr": completed.stderr,
                    "proof_path": proof_path,
                    "proof_event_count": proof_event_count,
                    "elapsed_ms": round((time.perf_counter() - start) * 1000.0, 2),
                }

            results = []
            with ThreadPoolExecutor(max_workers=len(ports)) as executor:
                future_to_port = {executor.submit(_run_port, port): port for port in ports}
                for future in as_completed(future_to_port):
                    results.append(future.result())

            failures = []
            for result in sorted(results, key=lambda item: int(item["port"])):
                if int(result["returncode"]) != 0:
                    failures.append(
                        f"port={result['port']} returncode={result['returncode']} elapsed_ms={result['elapsed_ms']}\nstdout={result['stdout']}\nstderr={result['stderr']}"
                    )
                    continue
                if "Transport:    official" not in str(result["stdout"]):
                    failures.append(
                        f"port={result['port']} missing official transport marker elapsed_ms={result['elapsed_ms']}\nstdout={result['stdout']}"
                    )
                    continue
                if not os.path.exists(str(result["proof_path"])) or int(result["proof_event_count"]) <= 0:
                    failures.append(
                        f"port={result['port']} invalid proof output elapsed_ms={result['elapsed_ms']} proof_path={result['proof_path']} proof_event_count={result['proof_event_count']}"
                    )
            self.assertFalse(failures, msg="\n\n".join(failures))


if __name__ == "__main__":
    unittest.main()
