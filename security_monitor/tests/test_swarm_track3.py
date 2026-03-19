import json
import os
import tempfile
import unittest

from security_monitor.swarm.demo_track3 import _create_agents, run_acceptance, run_demo, run_warmup
from security_monitor.swarm.messages import DISCOVER
from security_monitor.swarm.negotiation import select_winner
from security_monitor.swarm.security import verify_payload
from security_monitor.swarm.agent_node import SwarmNetwork


class Track3SwarmTests(unittest.TestCase):
    def test_full_loop_without_fault(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            summary = run_demo(output_dir=tmp, fault_mode="none")
            self.assertEqual(summary["winner"], "agent-worker-0")
            self.assertEqual(summary["signer_count"], len(summary["active_nodes"]))
            self.assertGreater(summary["event_count"], 0)
            self.assertTrue(os.path.exists(summary["event_log_path"]))
            self.assertTrue(os.path.exists(summary["proof_path"]))

    def test_loop_with_node_drop(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            summary = run_demo(output_dir=tmp, fault_mode="drop")
            self.assertEqual(summary["winner"], "agent-worker-1")
            self.assertEqual(summary["signer_count"], len(summary["active_nodes"]))

    def test_proof_has_hash_chain(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            summary = run_demo(output_dir=tmp, fault_mode="delay")
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
            summary = run_demo(output_dir=tmp, fault_mode="none")
            with open(summary["event_log_path"], "r", encoding="utf-8") as f:
                events = json.load(f)
            exec_done = [event for event in events if event["event_type"] == "EXEC_DONE"]
            self.assertEqual(len(exec_done), 1)

    def test_acceptance_bundle_exports_report(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            acceptance = run_acceptance(output_dir=tmp)
            self.assertTrue(os.path.exists(acceptance["report_path"]))
            self.assertTrue(all(acceptance["criteria"].values()))

    def test_hive_memory_gossip_recorded(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            summary = run_demo(output_dir=tmp, fault_mode="none")
            self.assertTrue(summary["checks"]["hive_memory_consistent"])
            with open(summary["event_log_path"], "r", encoding="utf-8") as f:
                events = json.load(f)
            gossip_events = [event for event in events if event["event_type"] == "THREAT_GOSSIP"]
            self.assertGreaterEqual(len(gossip_events), 1)

    def test_warmup_proof_flow(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            summary = run_warmup(
                output_dir=tmp,
                heartbeat_window_seconds=2,
                outage_seconds=1,
                heartbeat_seconds=0.1,
                stale_after_seconds=0.25,
            )
            self.assertTrue(os.path.exists(summary["proof_log_path"]))
            self.assertTrue(os.path.exists(summary["state_snapshot_path"]))
            self.assertTrue(all(summary["checks"].values()))
            self.assertLess(summary["mirror_latency_ms"], 1000.0)


if __name__ == "__main__":
    unittest.main()
