import os
import tempfile
import unittest

from security_monitor.warmup.protocol import run_warmup


class WarmupTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
