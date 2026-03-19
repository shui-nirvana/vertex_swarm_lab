# Vertex Swarm Lab - Track 3: Leaderless Swarm

This repository contains the implementation for the **Vertex Swarm Challenge 2026 - Track 3**.
The goal is to build a decentralized, leaderless swarm of agents capable of coordinating tasks, handling faults, and producing verifiable audit trails without a master orchestrator.

## Project Status

**Current Progress:** Day 5/7 (Hive Memory Implemented)

- [x] Core Swarm Protocol (Discover, Bid, Commit, Execute, Verify)
- [x] Leaderless Consensus (Deterministic Winner Selection)
- [x] Fault Injection & Resilience (Node Drop, Message Delay)
- [x] Cryptographic Audit Trail (Hash Chain, Multi-sig)
- [x] Acceptance Testing Suite (Automated Criteria Verification)
- [x] Scale Testing (Verified with 30+ Agents)
- [x] Hive Memory (Shared Threat Intelligence Gossip)

## Directory Structure

- `security_monitor/swarm/`: Core implementation.
  - `agent_node.py`: Main agent logic (State Machine).
  - `demo_track3.py`: CLI entry point for demos and tests.
  - `consensus.py`: Threshold voting logic.
  - `negotiation.py`: Winner selection logic.
  - `proof.py`: Audit trail generation.
- `security_monitor/tests/`: Unit tests.

## How to Run

### 1. Standard Demo (3 Agents)

Run a single scenario with default settings (3 agents, delay injection):

```bash
python -m security_monitor.swarm.demo_track3
```

### 2. Acceptance Suite

Run all scenarios (None, Delay, Drop) and verify against hackathon criteria:

```bash
python -m security_monitor.swarm.demo_track3 --mode acceptance
```

Output: `artifacts/acceptance_report.json`

### 3. Scale Test (10+ Agents)

Run the swarm with a custom number of worker agents (e.g., 30 workers + 1 planner):

```bash
python -m security_monitor.swarm.demo_track3 --mode single --workers 30 --fault drop
```

This demonstrates:

- **Scalability**: System handles O(N) message complexity.
- **Resilience**: Even if the expected winner drops (in `--fault drop` mode), the swarm converges on the next best candidate.

## Architecture Highlights

- **Leaderless**: No central coordinator. Agents self-organize via `TASK_OFFER` -> `BID` -> `COMMIT_VOTE` -> `EXECUTE` -> `VERIFY_ACK`.
- **Deterministic**: All agents reach the same conclusion given the same inputs using strict sorting rules (Price > ETA > ID).
- **Hive Memory**: Agents share "World View" (e.g., Threat Intelligence) via `THREAT_GOSSIP` events, updating local state without a central DB.
- **Verifiable**: Every step is hashed and linked. The final "Coordination Proof" is a multi-signature document proving consensus.
