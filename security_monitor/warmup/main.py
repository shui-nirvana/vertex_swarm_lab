import argparse
import os

from security_monitor.warmup.protocol import run_warmup


def main() -> int:
    parser = argparse.ArgumentParser(description="Warmup submission entrypoint")
    parser.add_argument(
        "--output-dir",
        default=os.path.join(os.getcwd(), "artifacts", "warmup"),
        help="Directory for warmup proof outputs",
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
