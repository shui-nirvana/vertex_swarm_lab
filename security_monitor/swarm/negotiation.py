from typing import Any, Dict, List


def select_winner(bids: List[Dict[str, Any]]) -> Dict[str, Any]:
    if not bids:
        raise ValueError("no bids available for winner selection")
    ordered = sorted(
        bids,
        key=lambda bid: (
            float(bid["price"]),
            int(bid["eta_ms"]),
            str(bid["agent_id"]),
        ),
    )
    return ordered[0]
