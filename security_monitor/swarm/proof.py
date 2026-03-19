import hashlib
import json
from typing import Any, Dict, List

from security_monitor.swarm.messages import EventRecord


def _event_digest(record: Dict[str, Any]) -> str:
    payload = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def build_hash_chain(events: List[EventRecord]) -> List[Dict[str, Any]]:
    chain: List[Dict[str, Any]] = []
    previous = "GENESIS"
    for event in events:
        event_dict = event.to_dict()
        digest = _event_digest(event_dict)
        chain_hash = hashlib.sha256(f"{previous}:{digest}".encode("utf-8")).hexdigest()
        chain_item = {
            "event": event_dict,
            "event_digest": digest,
            "prev_hash": previous,
            "chain_hash": chain_hash,
        }
        chain.append(chain_item)
        previous = chain_hash
    return chain


def build_proof(events: List[EventRecord], signatures: Dict[str, str]) -> Dict[str, Any]:
    chain = build_hash_chain(events)
    final_hash = chain[-1]["chain_hash"] if chain else "GENESIS"
    return {
        "event_count": len(events),
        "final_chain_hash": final_hash,
        "chain": chain,
        "multisig_summary": signatures,
    }
