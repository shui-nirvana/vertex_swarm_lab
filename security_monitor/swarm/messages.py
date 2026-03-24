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
SCAN_QUOTE = "SCAN_QUOTE"
NANOPAYMENT = "NANOPAYMENT"
SCAN_RESULT = "SCAN_RESULT"
THREAT_REPORT = "THREAT_REPORT"
THREAT_CONFIRM = "THREAT_CONFIRM"
BLOCK_EXEC = "BLOCK_EXEC"
REPUTATION_PENALTY = "REPUTATION_PENALTY"
ROUTE_PROPOSAL = "ROUTE_PROPOSAL"
ROUTE_COMMIT = "ROUTE_COMMIT"
TASK_HANDOFF = "TASK_HANDOFF"


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
