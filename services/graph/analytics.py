"""
Graph Centrality Analytics — Lateral movement detection via topology analysis.

Calculates Betweenness Centrality on the network relationship graph to
identify "bridge" nodes — hosts that serve as bottlenecks between otherwise
isolated subnets. A dev laptop with high centrality is a strong indicator
of compromise and lateral movement.

Algorithm:
    Betweenness Centrality = fraction of shortest paths passing through a node.
    High centrality + non-infrastructure role = suspicious bridge.

Integration:
    Called periodically by the AnalyzerEngine (e.g., every 60 seconds)
    or after significant graph updates. Generates alerts for suspicious
    high-centrality nodes.

References:
    - MITRE ATT&CK TA0008 (Lateral Movement)
    - Freeman, L.C. (1977) "A Set of Measures of Centrality Based on Betweenness"
"""
import time
import networkx as nx
from typing import Dict, List, Optional
from dataclasses import dataclass, field
from loguru import logger
from pkg.core.interfaces import GraphStore


@dataclass
class CentralityAlert:
    """A node flagged as a suspicious bridge in the network topology."""
    node_id: str
    centrality_score: float        # 0.0 to 1.0
    node_type: str                 # "internal", "external", "shadow"
    connections: int               # degree (in + out)
    connected_to: List[str]        # neighbor node IDs
    risk_assessment: str           # Human-readable assessment
    is_infrastructure: bool        # Is this node expected to be central?


# Known infrastructure nodes that are EXPECTED to have high centrality.
# These are suppressed from lateral movement alerts.
INFRASTRUCTURE_PATTERNS = [
    # DNS & network infra
    "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1",
    # Common gateways
    "192.168.1.1", "192.168.0.1", "10.0.0.1",
]

INFRASTRUCTURE_SUFFIXES = [
    ".1",       # Default gateways typically end in .1
]


class GraphAnalyzer:
    """
    Network topology analyzer for lateral movement detection.

    Builds a NetworkX graph from the GraphStore and calculates
    Betweenness Centrality to find suspicious bridge nodes.
    """

    def __init__(
        self,
        graph_store: GraphStore,
        centrality_threshold: float = 0.3,
        min_connections: int = 3,
        analysis_interval: float = 60.0,    # seconds between analysis runs
    ):
        self.graph_store = graph_store
        self.centrality_threshold = centrality_threshold
        self.min_connections = min_connections
        self.analysis_interval = analysis_interval

        self._last_analysis_time: float = 0
        self._known_bridges: Dict[str, float] = {}  # node_id -> centrality_score
        self._alert_history: List[CentralityAlert] = []

    def _is_infrastructure(self, node_id: str) -> bool:
        """Check if a node is expected infrastructure (should be central)."""
        if node_id in INFRASTRUCTURE_PATTERNS:
            return True
        if any(node_id.endswith(suffix) for suffix in INFRASTRUCTURE_SUFFIXES):
            return True
        return False

    def _is_internal(self, ip: str) -> bool:
        """Check if an IP is internal/private."""
        prefixes = ["192.168.", "10.0.", "172.16.", "127.0."]
        return any(ip.startswith(p) for p in prefixes)

    def should_analyze(self) -> bool:
        """Check if enough time has passed since last analysis."""
        return (time.time() - self._last_analysis_time) >= self.analysis_interval

    async def detect_lateral_movement(self) -> List[CentralityAlert]:
        """
        Analyze the network graph for lateral movement indicators.

        Builds a NetworkX DiGraph from the GraphStore, calculates
        betweenness centrality, and flags suspicious bridge nodes.

        Returns:
            List of CentralityAlert objects for suspicious nodes.
        """
        self._last_analysis_time = time.time()
        alerts = []

        try:
            # 1. Fetch graph data from the store
            nodes = await self.graph_store.get_all_nodes()
            edges = await self.graph_store.get_all_edges()

            if len(nodes) < 3 or len(edges) < 2:
                # Not enough data for meaningful analysis
                return alerts

            # 2. Build NetworkX graph
            G = nx.DiGraph()
            node_types = {}
            for node in nodes:
                node_id = node.get("id", "")
                node_type = node.get("type", "unknown")
                G.add_node(node_id)
                node_types[node_id] = node_type

            for edge in edges:
                src = edge.get("source", "")
                tgt = edge.get("target", "")
                if src and tgt:
                    G.add_edge(src, tgt)

            # 3. Calculate Betweenness Centrality
            try:
                centrality = nx.betweenness_centrality(G, normalized=True)
            except Exception as e:
                logger.debug(f"Centrality calculation failed: {e}")
                return alerts

            # 4. Identify suspicious bridge nodes
            for node_id, score in centrality.items():
                if score < self.centrality_threshold:
                    continue

                degree = G.degree(node_id)
                if degree < self.min_connections:
                    continue

                node_type = node_types.get(node_id, "unknown")
                is_infra = self._is_infrastructure(node_id)

                # Infrastructure nodes are expected to be central — skip
                if is_infra:
                    continue

                # Internal nodes with high centrality are the most suspicious
                # (indicates a compromised host bridging subnets)
                neighbors = list(G.predecessors(node_id)) + list(G.successors(node_id))
                neighbors = list(set(neighbors))[:20]  # Cap for performance

                # Check if this node bridges internal and external
                has_internal_neighbors = any(self._is_internal(n) for n in neighbors)
                has_external_neighbors = any(not self._is_internal(n) for n in neighbors)
                bridges_subnets = has_internal_neighbors and has_external_neighbors

                if bridges_subnets:
                    risk = (
                        f"HIGH RISK: Node {node_id} (centrality={score:.2f}) bridges "
                        f"internal and external networks with {degree} connections — "
                        f"potential lateral movement pivot point"
                    )
                elif self._is_internal(node_id):
                    risk = (
                        f"MEDIUM RISK: Internal node {node_id} (centrality={score:.2f}) "
                        f"has unusually high centrality with {degree} connections — "
                        f"monitor for compromise indicators"
                    )
                else:
                    risk = (
                        f"INFO: External node {node_id} (centrality={score:.2f}) "
                        f"acts as a hub with {degree} connections"
                    )

                alert = CentralityAlert(
                    node_id=node_id,
                    centrality_score=score,
                    node_type=node_type,
                    connections=degree,
                    connected_to=neighbors[:10],
                    risk_assessment=risk,
                    is_infrastructure=is_infra,
                )
                alerts.append(alert)

                # Track as known bridge
                prev_score = self._known_bridges.get(node_id)
                if prev_score is None:
                    logger.warning(
                        f"🕸 NEW BRIDGE NODE: {node_id} "
                        f"(centrality={score:.2f}, connections={degree})"
                    )
                elif score > prev_score * 1.2:  # 20% increase
                    logger.warning(
                        f"🕸 BRIDGE ESCALATION: {node_id} centrality increased "
                        f"{prev_score:.2f} → {score:.2f}"
                    )
                self._known_bridges[node_id] = score

            self._alert_history.extend(alerts)
            # Keep only last 100 alerts
            self._alert_history = self._alert_history[-100:]

            if alerts:
                logger.info(
                    f"🕸 Graph analysis complete: {len(alerts)} suspicious bridge nodes "
                    f"(total nodes: {len(nodes)}, edges: {len(edges)})"
                )

            return alerts

        except Exception as e:
            logger.error(f"Graph analysis failed: {e}")
            return []

    def get_topology_summary(self) -> Dict:
        """Get a summary of known topology for dashboard display."""
        return {
            "known_bridges": {
                node: {"centrality": score}
                for node, score in sorted(
                    self._known_bridges.items(),
                    key=lambda x: x[1],
                    reverse=True
                )[:10]
            },
            "total_bridges_detected": len(self._known_bridges),
            "recent_alerts": len(self._alert_history),
            "last_analysis": self._last_analysis_time,
        }
