import logging
from dataclasses import dataclass, field
from typing import Dict, Any, Optional

from security_monitor.swarm.agent_node import AgentNode
from security_monitor.integration.ai_engine import AIRiskEngine
from security_monitor.swarm.messages import THREAT_GOSSIP

logger = logging.getLogger(__name__)

@dataclass
class ScoutAgent(AgentNode):
    """
    Scout Agent: Responsible for threat detection and initial risk assessment.
    Uses AIRiskEngine to analyze potential threats.
    """
    ai_engine: AIRiskEngine = field(default_factory=AIRiskEngine)
    
    def __post_init__(self):
        # Override capability
        self.capability = "scout"

    def analyze_target(self, target_address: str, amount: float = 0.0) -> Dict[str, Any]:
        """Analyze a target using the AI Risk Engine."""
        logger.info(f"Scout {self.agent_id} analyzing target {target_address}")
        risk_assessment = self.ai_engine.analyze_defense_request(target_address, amount)
        
        if not risk_assessment.get("safe", False):
            logger.warning(f"Threat detected by {self.agent_id}: {risk_assessment}")
            self.broadcast_threat(target_address, risk_assessment)
            
        return risk_assessment

    def broadcast_threat(self, target: str, details: Dict[str, Any]) -> None:
        """Broadcast threat intelligence to the Hive Memory."""
        payload = {
            "target": target,
            "details": details,
            "reporter": self.agent_id
        }
        # In a real system, this would go to a gossip protocol
        # For now, we use the existing message structure if possible, 
        # or just log it if the message type isn't fully supported by the base class yet.
        # Checking base class... it has _broadcast but maybe not THREAT_GOSSIP handling fully wired?
        # The base class has `threat_ledger`.
        
        # We can simulate the message type
        self._broadcast("THREAT_GOSSIP", payload)
