# Vertex Swarm Lab - Track 3: Leaderless Swarm

This repository implements **Vertex Swarm Challenge 2026 - Track 3**.
It demonstrates a decentralized, leaderless swarm that coordinates tasks under contention, remains stable under faults, and produces verifiable coordination proofs without a central orchestrator.

## Project Status

- [x] Core Swarm Protocol (Discover, Bid, Commit, Execute, Verify)
- [x] Leaderless Deterministic Consensus
- [x] Fault Injection & Resilience (delay/drop)
- [x] Cryptographic Audit Trail (hash chain + multi-sig style proof)
- [x] Acceptance Suite (criteria-based)
- [x] Hive Memory (shared threat gossip)
- [x] Official FoxMQ backend execution (single-node and 4-node cluster)
- [x] Multi-vendor execution protocol coverage (ros2 / mavlink / vendor_sdk)
- [x] Multi-hop route negotiation and task handoff evidence

## Reviewer Quick Path

If you only have a few minutes, run these in order:

1. `python -m security_monitor.swarm.demo_track3 --mode acceptance --foxmq-backend simulated`
2. Open the generated `acceptance_report.json`
3. Confirm criteria and scenario checks are all `true`

For pre-validated hardened evidence, start here:

- MQTT: `artifacts/competition_req_check/acceptance_mqtt_10_hardened/acceptance_report.json`
- Official bridge: `artifacts/competition_req_check/acceptance_official_10_hardened/acceptance_report.json`

## README Update Rule

For every capability enhancement, update this file in the same change set:

- Update `Project Status` to reflect new capability flags
- Update `Run Guide` with reproducible command(s)
- Update `Architecture Highlights` with new system-level behavior
- If acceptance criteria changed, list the new criteria names

## Directory Structure

- `security_monitor/swarm/`: core swarm logic and CLI entry (`demo_track3.py`)
- `security_monitor/integration/`: transport and settlement integration (`foxmq_adapter.py`)
- `security_monitor/roles/`: scout / guardian / verifier behaviors
- `security_monitor/tests/`: e2e and acceptance-related tests

## Run Guide

### 1) Quick Demo

```bash
python -m security_monitor.swarm.demo_track3
```

### 2) Acceptance (Simulated Transport)

```bash
python -m security_monitor.swarm.demo_track3 --mode acceptance --foxmq-backend simulated
```

### 3) Acceptance (Official FoxMQ MQTT Endpoint)

Start `foxmq.exe` with a reachable MQTT listener (for Windows loopback, bind explicitly to `127.0.0.1`):

```bash
foxmq.exe run --secret-key-file=foxmq.d\key_0.pem --allow-anonymous-login --mqtt-addr=127.0.0.1:1883 --cluster-addr=127.0.0.1:19793
```

Then run acceptance against that endpoint:

```bash
python -m security_monitor.swarm.demo_track3 --mode acceptance --foxmq-backend mqtt --foxmq-mqtt-addr 127.0.0.1:1883
```

### 4) Acceptance Against 4-Node Cluster (3N+1, N=1)

Use four FoxMQ nodes with distinct ports:

- Node0: MQTT `127.0.0.1:1883`, Cluster `127.0.0.1:19793`
- Node1: MQTT `127.0.0.1:1884`, Cluster `127.0.0.1:19794`
- Node2: MQTT `127.0.0.1:1885`, Cluster `127.0.0.1:19795`
- Node3: MQTT `127.0.0.1:1886`, Cluster `127.0.0.1:19796`

Run acceptance against any active node endpoint:

```bash
python -m security_monitor.swarm.demo_track3 --mode acceptance --foxmq-backend mqtt --foxmq-mqtt-addr 127.0.0.1:1886
```

### 5) MQTT E2E Test

```bash
set MQTT_E2E=1
set FOXMQ_MQTT_ADDR=127.0.0.1:1884
python -m unittest security_monitor.tests.test_swarm_track3.Track3SwarmTests.test_mqtt_transport_demo_e2e
```

### 6) Reinforced Acceptance (10+ Agents + Multi-hop + Multi-vendor)

```bash
python -m security_monitor.swarm.demo_track3 --mode acceptance --workers 10 --foxmq-backend simulated --output-dir artifacts/competition_req_check/acceptance_simulated_10_reinforced
```

Expected additional criteria in `acceptance_report.json`:

- `multi_vendor_readiness`
- `route_negotiation_handoff`
- `task_bidding`
- `hive_memory_state_sync`
- `verification_multisig_proof`
- `byo_agents_orchestrator_replaced`
- `security_attack_resistance`
- `observability_kpi_ready`

## Artifact Outputs

Acceptance mode writes:

- `artifacts/<run_name>/acceptance_report.json`
- `artifacts/<run_name>/none|delay|drop/structured_event_log.json`
- `artifacts/<run_name>/none|delay|drop/coordination_proof.json`
- `artifacts/<run_name>/none|delay|drop/commit_log.json`

Latest validated evidence package:

- MQTT hardened acceptance: `artifacts/competition_req_check/acceptance_mqtt_10_hardened/acceptance_report.json`
- Official (Rust bridge) hardened acceptance: `artifacts/competition_req_check/acceptance_official_10_hardened/acceptance_report.json`
- Simulated hardened baseline: `artifacts/competition_req_check/acceptance_simulated_10_hardened/acceptance_report.json`

GitHub-friendly progress snapshot:

- `evidence/progress_evidence.json`

## Submission File Checklist

Recommended files/folders to submit:

- `README.md`
- `security_monitor/__init__.py`
- `security_monitor/swarm/`
- `security_monitor/integration/`
- `security_monitor/roles/`
- `security_monitor/tests/`
- `.gitignore`

Do not submit generated/runtime files:

- `artifacts/` (logs, reports, local binaries, temporary keys)
- Python caches (`__pycache__/`, `.pytest_cache/`, `.mypy_cache/`, `.ruff_cache/`)

If judges request evidence files, provide selected report artifacts as an attachment package instead of mixing generated files into source submission.

## Architecture Highlights

- **Leaderless Coordination**: no coordinator; agents converge through discover → bid → commit → execute → verify.
- **Deterministic Outcomes**: identical input yields identical winner resolution and commit behavior.
- **Fault Resilience**: delay/drop faults are injected while preserving progress and task completion.
- **Verifiable Audit Trail**: proof chain and signed acknowledgements support auditability and replay resistance.
- **Transport Pluggability**: simulated, MQTT, and official bridge-oriented paths are supported behind one adapter boundary.
- **Multi-Vendor Readiness**: worker execution includes protocol identity with ros2 / mavlink / vendor_sdk coverage in one run.
- **Multi-Hop Coordination**: route proposal, route commit, and per-hop handoff are all recorded and validated.
- **BYO Adapter Contract**: external orchestration integrates via adapter-level pre-execution context.
- **Quantified Observability**: acceptance reports include `p95_commit_latency_ms`, `verify_ack_ratio`, and `message_drop_recovery_time_ms`.

## Tashi Pillar Mapping

- **Python + FoxMQ**: implemented in `security_monitor/swarm/demo_track3.py` through `FoxMQAdapter`.
- **Bring Your Own Agents**: external-framework worker integration path (`langchain_adapter`) with orchestration driven by FoxMQ event flow.
- **Task Bidding**: offer/bid/commit pipeline with deterministic winner selection and no double assignment.
- **Hive Memory**: threat gossip synchronization across agents without a central database.
- **Verification**: hash-chain proof with multi-signed summary and verify acknowledgements.
- **Rust/C direct Vertex**: optional path; this repository currently uses Python + FoxMQ with a vertex-rs bridge integration boundary.

## Judging Criteria Mapping

- **Coordination Correctness** → `coordination_correctness` with `single_winner` and `no_double_assignment`
- **Resilience** → `resilience` under `delay` and `drop` fault scenarios
- **Auditability** → `auditability` with proof artifacts (`coordination_proof.json`, event chain, multisig summary)
- **Security Posture** → `security_posture` with signed envelopes, verify acknowledgements, and replay protection
- **Developer Clarity** → `developer_clarity` with runnable CLI flow and generated logs (`structured_event_log.json`, `commit_log.json`)
- **Security Hardening Evidence** → `security_attack_resistance` through forged-signature and replay rejection checks
- **Observability KPIs** → `observability_kpi_ready` with scenario KPI summary in acceptance report
