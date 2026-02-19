"""
Session Sequence Analyzer — Behavioral pattern detection.

Detects suspicious behavioral patterns across time, not just single flows.
Example: An employee who suddenly starts accessing AI services after months
of only using internal tools = behavioral anomaly.
"""
import numpy as np
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Dict, List, Tuple
from loguru import logger


class SessionAnalyzer:
    """
    Tracks per-IP session history and detects behavioral shifts.
    
    Unlike the anomaly/classifier models that look at individual flows,
    this analyzes patterns OVER TIME per source IP.
    """

    def __init__(self, window_minutes: int = 30):
        self.window = timedelta(minutes=window_minutes)
        # Per-IP history: { ip: [{ timestamp, dst, type, bytes }] }
        self.sessions: Dict[str, list] = defaultdict(list)
        # Per-IP baseline: { ip: { "avg_bytes": X, "top_dsts": [...], "patterns": {} } }
        self.baselines: Dict[str, dict] = {}

    def record(self, src_ip: str, dst: str, dst_type: str, 
               bytes_total: int, timestamp: datetime):
        """Record a flow event for session tracking."""
        self.sessions[src_ip].append({
            "timestamp": timestamp,
            "dst": dst,
            "type": dst_type,
            "bytes": bytes_total,
        })
        # Trim old entries outside the window
        cutoff = timestamp - self.window
        self.sessions[src_ip] = [
            e for e in self.sessions[src_ip] if e["timestamp"] > cutoff
        ]

    def analyze(self, src_ip: str) -> Dict:
        """
        Analyze an IP's recent session for behavioral anomalies.
        
        Returns:
            {
                "risk_score": float (0-1),
                "flags": ["BURST_AI_USAGE", "NEW_DESTINATION", ...],
                "ai_ratio": float,
                "unique_dsts": int,
                "total_flows": int,
            }
        """
        session = self.sessions.get(src_ip, [])
        if not session:
            return {"risk_score": 0.0, "flags": [], "ai_ratio": 0.0,
                    "unique_dsts": 0, "total_flows": 0}

        total = len(session)
        ai_flows = [e for e in session if e["type"] == "shadow"]
        ai_ratio = len(ai_flows) / max(total, 1)
        unique_dsts = len(set(e["dst"] for e in session))
        total_bytes = sum(e["bytes"] for e in session)

        flags = []
        risk_score = 0.0

        # Flag 1: High AI usage ratio
        if ai_ratio > 0.3:
            flags.append("HIGH_AI_RATIO")
            risk_score += 0.3

        # Flag 2: Burst AI usage (3+ AI accesses in short window)
        if len(ai_flows) >= 3:
            flags.append("BURST_AI_USAGE")
            risk_score += 0.25

        # Flag 3: Multiple unique AI services
        unique_ai = len(set(e["dst"] for e in ai_flows))
        if unique_ai >= 2:
            flags.append("MULTI_AI_SERVICES")
            risk_score += 0.2

        # Flag 4: Large data exfiltration to AI (sending big prompts)
        ai_bytes = sum(e["bytes"] for e in ai_flows)
        if ai_bytes > 100000:  # 100KB+
            flags.append("LARGE_AI_PAYLOAD")
            risk_score += 0.25

        # Flag 5: Unusual activity volume
        if total > 50:
            flags.append("HIGH_ACTIVITY")
            risk_score += 0.1

        return {
            "risk_score": min(risk_score, 1.0),
            "flags": flags,
            "ai_ratio": round(ai_ratio, 3),
            "unique_dsts": unique_dsts,
            "total_flows": total,
            "ai_bytes": ai_bytes if ai_flows else 0,
        }

    def get_all_risk_scores(self) -> List[Tuple[str, float]]:
        """Get risk scores for all tracked IPs, sorted highest first."""
        scores = []
        for ip in self.sessions:
            result = self.analyze(ip)
            scores.append((ip, result["risk_score"]))
        return sorted(scores, key=lambda x: x[1], reverse=True)
