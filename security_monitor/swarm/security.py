import hashlib
import hmac
import json
import time
from typing import Any, Dict, Optional, Set, Tuple


def canonical_json(data: Dict[str, Any]) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sign_payload(secret: str, data: Dict[str, Any]) -> str:
    payload = canonical_json(data).encode("utf-8")
    return hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).hexdigest()


def verify_payload(secret: str, data: Dict[str, Any], signature: str) -> bool:
    expected = sign_payload(secret, data)
    return hmac.compare_digest(expected, signature)


class ReplayProtector:
    def __init__(self, max_skew_seconds: float = 30.0):
        self.max_skew_seconds = max_skew_seconds
        self._seen: Set[Tuple[str, str]] = set()

    def check_and_mark(self, sender: str, nonce: str, ts: float) -> Tuple[bool, Optional[str]]:
        now = time.time()
        if abs(now - ts) > self.max_skew_seconds:
            return False, "timestamp_out_of_window"
        key = (sender, nonce)
        if key in self._seen:
            return False, "replay_detected"
        self._seen.add(key)
        return True, None
