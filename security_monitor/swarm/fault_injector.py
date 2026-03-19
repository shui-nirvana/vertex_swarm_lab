import time
from dataclasses import dataclass, field
from typing import Dict, Set


@dataclass
class FaultInjector:
    dropped_nodes: Set[str] = field(default_factory=set)
    delayed_messages_ms: Dict[str, int] = field(default_factory=dict)

    def is_node_dropped(self, node_id: str) -> bool:
        return node_id in self.dropped_nodes

    def apply_delay(self, message_type: str) -> None:
        delay_ms = self.delayed_messages_ms.get(message_type, 0)
        if delay_ms > 0:
            time.sleep(delay_ms / 1000)
