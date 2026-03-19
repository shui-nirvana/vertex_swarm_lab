from dataclasses import dataclass
from typing import Any, Dict

DISCOVER = "DISCOVER"
HEARTBEAT = "HEARTBEAT"
TASK_OFFER = "TASK_OFFER"
BID = "BID"
COMMIT_VOTE = "COMMIT_VOTE"
EXEC_START = "EXEC_START"
EXEC_DONE = "EXEC_DONE"
VERIFY_ACK = "VERIFY_ACK"
THREAT_GOSSIP = "THREAT_GOSSIP"  # Hive Memory: Shared threat intelligence


@dataclass(frozen=True)
class EventRecord:
    ts: float
    actor: str
    event_type: str
    payload: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ts": self.ts,
            "actor": self.actor,
            "event_type": self.event_type,
            "payload": self.payload,
        }
