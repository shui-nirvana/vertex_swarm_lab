import logging
from dataclasses import dataclass
from typing import Dict, Any

from security_monitor.swarm.agent_node import AgentNode
from security_monitor.swarm.messages import VERIFY_ACK

logger = logging.getLogger(__name__)

@dataclass
class VerifierAgent(AgentNode):
    """
    Verifier Agent: Responsible for post-execution validation and consensus.
    Ensures that reported actions match the on-chain reality or agreed-upon rules.
    """
    
    def __post_init__(self):
        # Override capability
        self.capability = "verifier"

    def _maybe_bid(self, offer: Dict[str, Any]) -> None:
        """Verifier does not bid on tasks."""
        pass

    def verify_execution(self, task_id: str, executor_id: str, result: Dict[str, Any]) -> bool:
        """
        Verify the execution result of another agent.
        In a real scenario, this would check on-chain events or cryptographic proofs.
        """
        logger.info(f"Verifier {self.agent_id} checking task {task_id} by {executor_id}")
        
        # Simple verification logic: check if 'success' is True and signature exists
        is_valid = result.get("success", False)
        if "tx_hash" in result:
            # Simulate checking if tx exists on chain
            is_valid = is_valid and result["tx_hash"].startswith("0x")
            
        if is_valid:
            logger.info(f"Task {task_id} verified successfully by {self.agent_id}")
            self._broadcast(VERIFY_ACK, {
                "task_id": task_id,
                "verifier": self.agent_id,
                "valid": True
            })
        else:
            logger.warning(f"Task {task_id} verification failed by {self.agent_id}")
            
        return is_valid
