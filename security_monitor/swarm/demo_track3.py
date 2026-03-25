import argparse
import os

from security_monitor.warmup.protocol import run_warmup


def main() -> int:
    parser = argparse.ArgumentParser(description="Compatibility entrypoint for warmup replay")
    parser.add_argument("--mode", default="warmup")
    parser.add_argument("--output-dir", default=os.path.join(os.getcwd(), "artifacts_warmup_proof"))
    parser.add_argument("--warmup-window-seconds", type=int, default=30)
    parser.add_argument("--warmup-outage-seconds", type=int, default=10)
    parser.add_argument("--heartbeat-seconds", type=float, default=1.0)
    parser.add_argument("--stale-after-seconds", type=float, default=3.0)
    parser.add_argument(
        "--foxmq-backend",
        choices=["simulated", "official", "mqtt"],
        default=os.getenv("FOXMQ_BACKEND", "mqtt"),
    )
    parser.add_argument("--vertex-rs-bridge-cmd", default=os.getenv("VERTEX_RS_BRIDGE_CMD", ""))
    parser.add_argument("--foxmq-mqtt-addr", default=os.getenv("FOXMQ_MQTT_ADDR", "127.0.0.1:1883"))
    args = parser.parse_args()

    if args.mode != "warmup":
        raise SystemExit("This repository is warmup-only. Use --mode warmup.")

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
    print("\nWARMUP SUMMARY")
    print(f"Proof Log:    {warmup['proof_log_path']}")
    print(f"State File:   {warmup['state_snapshot_path']}")
    print(f"Mirror Latency(ms): {warmup['mirror_latency_ms']}")
    print(f"Transport:    {warmup['transport_backend']}")
    print(f"Checks:       {warmup['checks']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
