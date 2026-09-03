"""
NEXUS-SHIELD: Composite Threat & Risk Scoring Engine
Aggregates multidimensional indicators (scan patterns, lateral jumps, high-entropy DNS,
target asset criticality, and blast radius) into a normalized 0-100 risk index.
"""

from dataclasses import dataclass
from typing import Dict, List, Optional


@dataclass
class RiskEvaluation:
    source_ip: str
    composite_score: int
    severity: str  # SAFE, LOW, MEDIUM, HIGH, CRITICAL
    contributing_factors: List[str]
    recommended_action: str


class RiskScorer:
    """Calculates threat confidence and severity scores."""

    # Weights for risk calculation
    WEIGHTS = {
        "VERTICAL_PORT_SCAN": 35,
        "HORIZONTAL_NETWORK_SWEEP": 40,
        "LATERAL_MOVEMENT_PEER": 45,
        "LATERAL_MOVEMENT_CHAIN": 65,
        "DNS_TUNNEL_ANOMALY": 50,
        "CRITICAL_TARGET_HIT": 30,
        "NEW_UNSEEN_PORT": 15,
    }

    def evaluate(
        self,
        source_ip: str,
        detected_signals: List[str],
        target_criticality: str = "Medium",
        blast_score: int = 0,
    ) -> RiskEvaluation:
        score = 0
        factors = []

        for signal in detected_signals:
            weight = self.WEIGHTS.get(signal, 10)
            score += weight
            factors.append(f"{signal} (+{weight} pts)")

        if target_criticality == "Critical":
            score += 25
            factors.append("Target is Critical Infrastructure (+25 pts)")
        elif target_criticality == "High":
            score += 15
            factors.append("Target is High-Value Server (+15 pts)")

        if blast_score > 50:
            boost = int((blast_score - 50) * 0.4)
            score += boost
            factors.append(f"High Blast Radius Multiplier (+{boost} pts)")

        score = min(100, score)

        if score >= 85:
            severity = "CRITICAL"
            action = "IMMEDIATE HOST ISOLATION (QUARANTINE) & SEVER CONNECTIONS"
        elif score >= 70:
            severity = "HIGH"
            action = "RESTRICT TO MONITORING VLAN & ALERT SOC LEAD"
        elif score >= 50:
            severity = "MEDIUM"
            action = "FLAG HOST FOR ENHANCED BEHAVIORAL LOGGING"
        elif score >= 30:
            severity = "LOW"
            action = "RECORD IN RECONNAISSANCE AUDIT TRAIL"
        else:
            severity = "SAFE"
            action = "NO ACTION REQUIRED"

        return RiskEvaluation(
            source_ip=source_ip,
            composite_score=score,
            severity=severity,
            contributing_factors=factors,
            recommended_action=action,
        )
