import logging
import time
from dataclasses import dataclass, field
from typing import Dict, Any, Optional

from security_monitor.swarm.agent_node import AgentNode
from security_monitor.integration.wdk_settlement import WDKSettlementAdapter
from security_monitor.integration.settlement import SettlementEngine
from security_monitor.swarm.messages import EXEC_START, EXEC_DONE

logger = logging.getLogger(__name__)

@dataclass
class GuardianAgent(AgentNode):
    """
    Guardian Agent: Responsible for active defense and transaction execution.
    Handles settlement and execution logic using WDKSettlementAdapter.
    """
    settlement_engine: WDKSettlementAdapter = field(default_factory=WDKSettlementAdapter)
    
    def __post_init__(self):
        # Override capability
        self.capability = "guardian"

    def execute_committed_task(self, task_id: str) -> Optional[Dict[str, Any]]:
        """
        Execute a task using the WDK logic when committed.
        """
        winner = self.committed_winner_by_task.get(task_id)
        if winner != self.agent_id:
            return None
            
        offer = self.offers.get(task_id)
        if not offer:
            return None
            
        # Broadcast start
        self._broadcast(EXEC_START, {"task_id": task_id, "worker_id": self.agent_id})
        
        # Parse offer
        target = offer.get("mission", "unknown-target")
        budget = float(offer.get("budget_ceiling", 0.0))
        
        # Execute defense logic
        wdk_result = self.execute_defense(target, budget)
        
        # Create result payload
        result = {
            "task_id": task_id,
            "worker_id": self.agent_id,
            "status": "success" if wdk_result.get("success") else "failed",
            "wdk_tx": wdk_result.get("tx_hash"),
            "result_digest": wdk_result.get("tx_hash", "failed-digest"),
            "timestamp": time.time()
        }
        
        self.executions[task_id] = result
        
        # Broadcast done
        self._broadcast(EXEC_DONE, {
            "task_id": task_id,
            "worker_id": self.agent_id,
            "result_digest": result["result_digest"],
            "wdk_tx": result.get("wdk_tx")
        })
        
        return result

    def execute_defense(self, target: str, amount: float, token: str = "USDT") -> Dict[str, Any]:
        """Execute a defense action (e.g., token transfer or allowance check)."""
        logger.info(f"Guardian {self.agent_id} initiating defense for {target}")
        
        # Simulate check before action
        balance = self.settlement_engine.get_balance(self.agent_id, token)
        if balance < amount:
            logger.error(f"Insufficient funds for defense: {balance} < {amount}")
            return {"status": "failed", "reason": "insufficient_funds"}

        # Execute transfer (simulated)
        # Assuming the defense involves paying a fee or interacting with a contract
        # Here we simulate paying the target (or a defense contract)
        result = self.settlement_engine.transfer(
            from_address=self.agent_id,
            to_address=target,
            amount=amount,
            token=token
        )
        
        if result["success"]:
            logger.info(f"Defense executed successfully: {result['tx_hash']}")
            self._broadcast(EXEC_START, {
                "task_id": f"defense-{target}",
                "executor": self.agent_id,
                "tx_hash": result["tx_hash"]
            })
        else:
            logger.error(f"Defense execution failed: {result.get('error')}")
            
        return result
