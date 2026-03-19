import hashlib
import json
import time
from typing import Any, Dict


def execute_task(task: Dict[str, Any], worker_id: str) -> Dict[str, Any]:
    started_at = time.time()
    result = {
        "task_id": task["task_id"],
        "worker_id": worker_id,
        "status": "completed",
        "output": f"processed:{task['mission']}",
        "started_at": started_at,
        "finished_at": time.time(),
    }
    serialized = json.dumps(result, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    result["result_digest"] = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
    return result
