from collections import Counter
from typing import Dict, Iterable, Optional


def threshold_for(total_nodes: int) -> int:
    return (2 * total_nodes) // 3 + 1


def resolve_commit(votes: Iterable[Dict[str, str]], total_nodes: int) -> Optional[str]:
    counter = Counter(vote["winner"] for vote in votes)
    required = threshold_for(total_nodes)
    for winner, count in counter.items():
        if count >= required:
            return winner
    return None
