"""
Session Sequence Analyzer — Behavioral pattern detection.

Detects suspicious behavioral patterns across time, not just single flows.
Example: An employee who suddenly starts accessing AI services after months
of only using internal tools = behavioral anomaly.

v2: Added temporal clustering (inter-arrival time analysis) and
    data exfiltration velocity tracking for improved accuracy.
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
                "avg_inter_arrival_ms": float,
                "exfil_velocity_kbps": float,
            }
        """
        session = self.sessions.get(src_ip, [])
        if not session:
            return {"risk_score": 0.0, "flags": [], "ai_ratio": 0.0,
                    "unique_dsts": 0, "total_flows": 0,
                    "avg_inter_arrival_ms": 0.0, "exfil_velocity_kbps": 0.0}

        total = len(session)
        ai_flows = [e for e in session if e["type"] == "shadow"]
        ai_ratio = len(ai_flows) / max(total, 1)
        unique_dsts = len(set(e["dst"] for e in session))
        total_bytes = sum(e["bytes"] for e in session)

        flags = []
        risk_score = 0.0

        # ── Existing behavioral flags ──

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

        # ── New temporal & velocity flags ──

        # Flag 6: Rapid-fire AI requests (inter-arrival time analysis)
        avg_iat_ms = 0.0
        if len(ai_flows) >= 2:
            timestamps = sorted(e["timestamp"] for e in ai_flows)
            intervals = [(timestamps[i + 1] - timestamps[i]).total_seconds() * 1000
                         for i in range(len(timestamps) - 1)]
            avg_iat_ms = sum(intervals) / len(intervals)
            if avg_iat_ms < 5000:  # < 5 seconds between AI requests
                flags.append("RAPID_AI_REQUESTS")
                risk_score += 0.15

        # Flag 7: Data exfiltration velocity (KB/s to AI services)
        exfil_velocity = 0.0
        if ai_flows and len(ai_flows) >= 2:
            timestamps = sorted(e["timestamp"] for e in ai_flows)
            duration_s = max((timestamps[-1] - timestamps[0]).total_seconds(), 1.0)
            exfil_velocity = (ai_bytes / 1024.0) / duration_s  # KB/s
            if exfil_velocity > 50.0:  # > 50 KB/s sustained to AI
                flags.append("HIGH_EXFIL_VELOCITY")
                risk_score += 0.2

        # Flag 8: After-hours AI usage (before 8am or after 7pm)
        recent_ts = session[-1]["timestamp"]
        if recent_ts.hour < 8 or recent_ts.hour >= 19:
            if ai_flows:
                flags.append("AFTER_HOURS_AI")
                risk_score += 0.15

        return {
            "risk_score": min(risk_score, 1.0),
            "flags": flags,
            "ai_ratio": round(ai_ratio, 3),
            "unique_dsts": unique_dsts,
            "total_flows": total,
            "ai_bytes": ai_bytes if ai_flows else 0,
            "avg_inter_arrival_ms": round(avg_iat_ms, 1),
            "exfil_velocity_kbps": round(exfil_velocity, 2),
        }

    def get_all_risk_scores(self) -> List[Tuple[str, float]]:
        """Get risk scores for all tracked IPs, sorted highest first."""
        scores = []
        for ip in self.sessions:
            result = self.analyze(ip)
            scores.append((ip, result["risk_score"]))
        return sorted(scores, key=lambda x: x[1], reverse=True)
