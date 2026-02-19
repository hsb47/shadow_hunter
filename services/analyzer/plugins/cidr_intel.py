"""
CIDR Threat Intelligence Plugin — IP-level AI provider detection.

Catches Shadow AI traffic that bypasses DNS by matching destination IPs
against known CIDR blocks owned by AI providers (OpenAI, Anthropic, etc.).

Auto-loaded by the AnomalyDetector's plugin system — zero config needed.
"""
from typing import Tuple, Optional
from pkg.models.events import NetworkFlowEvent
from pkg.data.cidr_threat_intel import CIDRMatcher
from services.analyzer.plugin_base import DetectionPlugin


class CIDRIntelPlugin(DetectionPlugin):
    """Detects traffic to known AI provider IP ranges via CIDR matching."""

    name = "CIDR Threat Intelligence"
    description = "Matches destination IPs against known AI provider CIDR blocks"

    def __init__(self):
        self.matcher = CIDRMatcher()

    def detect(self, event: NetworkFlowEvent) -> Tuple[bool, Optional[str], Optional[str]]:
        match = self.matcher.lookup(event.destination_ip)
        if match:
            reason = (
                f"CIDR Intel: IP {event.destination_ip} belongs to "
                f"{match.provider} ({match.service}) "
                f"[{match.category}] — {match.data_risk}"
            )
            return True, match.risk_level, reason

        return False, None, None
