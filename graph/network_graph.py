"""
NEXUS-SHIELD: Dynamic In-Memory Network Graph Engine
Maintains nodes (assets) and directed edges (traffic flows) with real-time weights,
attack surfaces, and topological reachability.
"""

from dataclasses import dataclass
from typing import Dict, List, Set, Any
import math


@dataclass
class GraphNode:
    id: str
    label: str
    role: str
    criticality: str
    risk_score: int
    status: str
    open_ports: List[int]


@dataclass
class GraphEdge:
    source: str
    target: str
    protocol: str
    port: int
    packet_count: int
    byte_count: int
    is_anomalous: bool = False


class NetworkSecurityGraph:
    """Graph structure representing live network topology and communication relationships."""

    def __init__(self):
        self.nodes: Dict[str, GraphNode] = {}
        self.adjacency: Dict[str, Dict[str, GraphEdge]] = {}

    def upsert_node(
        self,
        node_id: str,
        role: str = "Workstation",
        criticality: str = "Medium",
        risk_score: int = 0,
        status: str = "NORMAL",
        open_ports: List[int] = None,
    ) -> None:
        if node_id not in self.adjacency:
            self.adjacency[node_id] = {}

        self.nodes[node_id] = GraphNode(
            id=node_id,
            label=node_id,
            role=role,
            criticality=criticality,
            risk_score=risk_score,
            status=status,
            open_ports=open_ports or [],
        )

    def add_flow_edge(
        self,
        src: str,
        dst: str,
        protocol: str,
        port: int,
        packets: int = 1,
        bytes_transferred: int = 64,
        is_anomalous: bool = False,
    ) -> None:
        if src not in self.adjacency:
            self.upsert_node(src)
        if dst not in self.adjacency:
            self.upsert_node(dst)

        if dst in self.adjacency[src]:
            edge = self.adjacency[src][dst]
            edge.packet_count += packets
            edge.byte_count += bytes_transferred
            if is_anomalous:
                edge.is_anomalous = True
        else:
            self.adjacency[src][dst] = GraphEdge(
                source=src,
                target=dst,
                protocol=protocol,
                port=port,
                packet_count=packets,
                byte_count=bytes_transferred,
                is_anomalous=is_anomalous,
            )

    def find_shortest_attack_path(self, start_node: str, target_node: str) -> List[str]:
        """Breadth-First Search (BFS) for shortest reachable path between nodes."""
        if start_node not in self.adjacency or target_node not in self.adjacency:
            return []

        queue = [[start_node]]
        visited = {start_node}

        while queue:
            path = queue.pop(0)
            current = path[-1]

            if current == target_node:
                return path

            for neighbor in self.adjacency.get(current, {}):
                if neighbor not in visited:
                    visited.add(neighbor)
                    new_path = list(path)
                    new_path.append(neighbor)
                    queue.append(new_path)

        return []

    def calculate_blast_radius(self, compromised_ip: str) -> Dict[str, Any]:
        """Calculates reachable high-value targets if compromised_ip is controlled by an attacker."""
        reachable_nodes: Set[str] = set()
        critical_targets_at_risk: List[Dict[str, Any]] = []

        visited = {compromised_ip}
        queue = [compromised_ip]

        while queue:
            curr = queue.pop(0)
            for neighbor in self.adjacency.get(curr, {}):
                if neighbor not in visited:
                    visited.add(neighbor)
                    reachable_nodes.add(neighbor)
                    queue.append(neighbor)
                    node_obj = self.nodes.get(neighbor)
                    if node_obj and node_obj.criticality in {"Critical", "High"}:
                        path = self.find_shortest_attack_path(compromised_ip, neighbor)
                        critical_targets_at_risk.append({
                            "target_ip": neighbor,
                            "role": node_obj.role,
                            "criticality": node_obj.criticality,
                            "path": path,
                        })

        return {
            "compromised_node": compromised_ip,
            "total_reachable_count": len(reachable_nodes),
            "critical_targets_at_risk": critical_targets_at_risk,
            "blast_score": min(100, len(reachable_nodes) * 15 + len(critical_targets_at_risk) * 25),
        }

    def export_graph_json(self) -> Dict[str, Any]:
        """Exports graph in D3/Cytoscape format for visualization dashboard."""
        nodes_data = [
            {
                "id": n.id,
                "label": n.label,
                "role": n.role,
                "criticality": n.criticality,
                "risk_score": n.risk_score,
                "status": n.status,
                "open_ports": n.open_ports,
            }
            for n in self.nodes.values()
        ]
        edges_data = []
        for src, neighbors in self.adjacency.items():
            for dst, edge in neighbors.items():
                edges_data.append({
                    "source": edge.source,
                    "target": edge.target,
                    "protocol": edge.protocol,
                    "port": edge.port,
                    "packet_count": edge.packet_count,
                    "byte_count": edge.byte_count,
                    "is_anomalous": edge.is_anomalous,
                })

        return {"nodes": nodes_data, "edges": edges_data}
