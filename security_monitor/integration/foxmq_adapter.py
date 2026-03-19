import logging
from typing import Dict, Any, List, Callable, Optional
import time
import uuid

logger = logging.getLogger(__name__)

class FoxMQAdapter:
    """
    Simulates a P2P message bus for decentralized agent communication.
    In a real implementation, this would wrap a libp2p or MQTT client.
    """
    
    def __init__(self, node_id: Optional[str] = None):
        self.node_id = node_id or f"node-{uuid.uuid4().hex[:8]}"
        self.peers: List[str] = []
        # In-memory subscription map: topic -> list of callbacks
        # Note: In a real distributed system, this would be handled by the network layer.
        # For simulation, we'll use a shared static registry if we want nodes to talk to each other in the same process,
        # or just instance-level for now if we are orchestrating from outside.
        # To make it work for the demo where multiple agents run in one process, 
        # we'll use a class-level shared bus.
        self._subscriptions: Dict[str, List[Callable[[Dict[str, Any]], None]]] = {}

    # Shared bus state for simulation within a single process
    _shared_bus: Dict[str, List[Callable[[Dict[str, Any]], None]]] = {}
    _shared_peers: List[str] = []

    def join_network(self, topic: str = "default") -> None:
        """Simulate joining the P2P network."""
        if self.node_id not in FoxMQAdapter._shared_peers:
            FoxMQAdapter._shared_peers.append(self.node_id)
        logger.info(f"Node {self.node_id} joined network topic '{topic}'")

    def leave_network(self) -> None:
        """Simulate leaving the P2P network."""
        if self.node_id in FoxMQAdapter._shared_peers:
            FoxMQAdapter._shared_peers.remove(self.node_id)
        logger.info(f"Node {self.node_id} left network")

    def subscribe(self, topic: str, callback: Callable[[Dict[str, Any]], None]) -> None:
        """Subscribe to a specific topic."""
        if topic not in FoxMQAdapter._shared_bus:
            FoxMQAdapter._shared_bus[topic] = []
        FoxMQAdapter._shared_bus[topic].append(callback)
        logger.debug(f"Node {self.node_id} subscribed to {topic}")

    def publish(self, topic: str, message: Dict[str, Any]) -> None:
        """Publish a message to a topic."""
        # Add metadata
        msg_with_meta = message.copy()
        msg_with_meta["_sender"] = self.node_id
        msg_with_meta["_timestamp"] = time.time()
        
        # Simulate network delay or delivery
        if topic in FoxMQAdapter._shared_bus:
            for callback in FoxMQAdapter._shared_bus[topic]:
                try:
                    callback(msg_with_meta)
                except Exception as e:
                    logger.error(f"Error processing message on topic {topic}: {e}")

    def broadcast(self, message: Dict[str, Any]) -> None:
        """Broadcast to a default 'global' topic."""
        self.publish("global", message)

    def get_active_peers(self) -> List[str]:
        """Return list of known active peers."""
        return [p for p in FoxMQAdapter._shared_peers if p != self.node_id]

    @classmethod
    def reset_simulation(cls) -> None:
        """Reset the shared bus state (for testing)."""
        cls._shared_bus = {}
        cls._shared_peers = []
