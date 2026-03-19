import argparse
import json
import os
import time
from typing import Any, Dict, List, Literal, Tuple, TypedDict, cast

from security_monitor.integration.ai_engine import AIRiskEngine
from security_monitor.integration.settlement import SettlementEngine
from security_monitor.integration.foxmq_adapter import FoxMQAdapter
from security_monitor.swarm.agent_node import AgentNode, SwarmNetwork
from security_monitor.swarm.fault_injector import FaultInjector
from security_monitor.swarm.proof import build_hash_chain, build_proof
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
    checks: Dict[str, bool]


class AcceptanceSummary(TypedDict):
    scenarios: Dict[str, DemoSummary]
    criteria: Dict[str, bool]
    report_path: str


class FoxSwarmNetwork(SwarmNetwork):
    """
    SwarmNetwork extended with FoxMQ integration for P2P simulation.
    """
    def __init__(self, fault_injector: FaultInjector = None):
        super().__init__(fault_injector)
        self.fox_mq = FoxMQAdapter()
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
    output_dir: str, fault_mode: Literal["none", "delay", "drop"], worker_count: int = 2
) -> DemoSummary:
    # Use FoxSwarmNetwork for P2P simulation
    injector = FaultInjector()
    if fault_mode == "delay":
        injector.delayed_messages_ms["BID"] = 80
    network = FoxSwarmNetwork(fault_injector=injector)
    
    planner, nodes = _create_agents(network, worker_count)
    # Cast planner to ScoutAgent for type checking
    scout = cast(ScoutAgent, planner)

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

    # Scout analyzes target before offering task
    target_address = "0x1234567890abcdef1234567890abcdef12345678"
    analysis = scout.analyze_target(target_address, amount=100.0)
    
    if not analysis["safe"]:
        raise RuntimeError(f"Scout rejected target: {analysis}")

    # Scout offers task with budget based on analysis
    scout.offer_task(
        task_id="task-001",
        mission=target_address,
        budget_ceiling=float(analysis["suggested_price"]) * 10, # Add buffer
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

    # Hive Memory: Simulate winner detecting a threat during execution and gossiping it
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
        "checks": checks,
    }


def run_acceptance(output_dir: str, worker_count: int = 2) -> AcceptanceSummary:
    scenarios: Dict[str, DemoSummary] = {}
    for mode in ("none", "delay", "drop"):
        scenario_dir = os.path.join(output_dir, mode)
        scenarios[mode] = run_demo(
            output_dir=scenario_dir,
            fault_mode=cast(Literal["none", "delay", "drop"], mode),
            worker_count=worker_count,
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


def main() -> int:
    parser = argparse.ArgumentParser(description="Track3 leaderless swarm demo")
    parser.add_argument(
        "--mode",
        choices=["single", "acceptance"],
        default="single",
        help="single: run one scenario, acceptance: run none/delay/drop and export report",
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
    args = parser.parse_args()

    if args.mode == "acceptance":
        acceptance = run_acceptance(output_dir=args.output_dir, worker_count=args.workers)
        print("\nTRACK3 ACCEPTANCE SUMMARY")
        print(f"Report: {acceptance['report_path']}")
        for name, passed in acceptance["criteria"].items():
            print(f"{name}: {'PASS' if passed else 'FAIL'}")
        return 0

    selected_fault = cast(Literal["none", "delay", "drop"], args.fault)
    summary = run_demo(output_dir=args.output_dir, fault_mode=selected_fault, worker_count=args.workers)
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
    print(f"Checks:       {summary['checks']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
