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

### 4. Warm-Up Proof (Discovery + Heartbeats + Shared State + Recovery)

Run the warm-up flow required by the challenge:

```bash
python -m security_monitor.swarm.demo_track3 --mode warmup --warmup-window-seconds 30 --warmup-outage-seconds 10
```

Generated artifacts:

- `artifacts/warmup_terminal_log.jsonl`: discovery, signed hello, heartbeat, stale/recovery event logs.
- `artifacts/warmup_state_snapshot.json`: replicated peer state with `peer_id`, `last_seen_ms`, `role`, `status`.

Quick capture command for short local verification:

```bash
python -m security_monitor.swarm.demo_track3 --mode warmup --warmup-window-seconds 5 --warmup-outage-seconds 2 --heartbeat-seconds 0.2 --stale-after-seconds 0.5
```

## Architecture Highlights

- **Leaderless**: No central coordinator. Agents self-organize via `TASK_OFFER` -> `BID` -> `COMMIT_VOTE` -> `EXECUTE` -> `VERIFY_ACK`.
- **Deterministic**: All agents reach the same conclusion given the same inputs using strict sorting rules (Price > ETA > ID).
- **Hive Memory**: Agents share "World View" (e.g., Threat Intelligence) via `THREAT_GOSSIP` events, updating local state without a central DB.
- **Verifiable**: Every step is hashed and linked. The final "Coordination Proof" is a multi-signature document proving consensus.
- **Vertex-Ready Integration**: The FoxMQ adapter is an interface layer for P2P messaging and is structured as a drop-in replacement point for direct Vertex/Tashi transport integration.
