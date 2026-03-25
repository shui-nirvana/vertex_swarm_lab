# Vertex Swarm Lab - Warmup (Stateful Handshake)

This repository is now **Warmup-only** and preserves the previously submitted, reproducible Warmup implementation and evidence path.

Validated result:

- Track3 Warmup completed (MQTT backend): discovery/handshake/heartbeats, state sync (<1s), and stale/recovery all passed (Mirror Latency: 11.087 ms).
- GitHub: `https://github.com/shui-nirvana/vertex_swarm_lab`
- Demo: `https://www.youtube.com/watch?v=2YVI8DLa0Po`

## Directory Structure

- `security_monitor/warmup/`: warmup entrypoint + protocol (`main.py`, `protocol.py`)
- `security_monitor/integration/`: FoxMQ transport adapter (`foxmq_adapter.py`)
- `security_monitor/swarm/security.py`: payload signing/verification utility used by warmup

## Run Guide

```bash
python -m security_monitor.warmup.main --foxmq-backend mqtt --foxmq-mqtt-addr 127.0.0.1:1883 --output-dir artifacts/warmup_only --warmup-window-seconds 30 --warmup-outage-seconds 10 --heartbeat-seconds 1.0 --stale-after-seconds 3.0
```

Warmup acceptance focus:

- Discovery + signed handshake + active heartbeats (30–60s)
- Replicated JSON state fields: `peer_id`, `last_seen_ms`, `role`, `status`
- Role toggle mirror (<1s): Agent A switches to `scout`, Agent B mirrors
- Failure injection: stop one node for 10s, mark peer stale, then auto-recover

## Note

Track3 implementation has been moved to a separate directory for independent repository submission; this repository no longer contains Track3 code paths.
