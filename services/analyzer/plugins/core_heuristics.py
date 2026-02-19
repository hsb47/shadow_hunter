"""
Core Heuristics Plugin — Built-in detection rules migrated from the original detector.

Contains the foundational rule-based detection logic:
1. Known AI Domain detection (via DPI hostname matching)
2. Unusual outbound port detection
3. DNS tunneling detection
"""
import random
from typing import Tuple, Optional
from pkg.models.events import NetworkFlowEvent, Protocol
from pkg.data.ai_domains import is_ai_domain, get_ai_category
from services.analyzer.plugin_base import DetectionPlugin


class AIDomainDetector(DetectionPlugin):
    """Detects traffic to known AI/ML service domains."""

    name = "AI Domain Detector"
    description = "Flags traffic to known AI services (ChatGPT, Claude, Gemini, etc.)"

    def detect(self, event: NetworkFlowEvent) -> Tuple[bool, Optional[str], Optional[str]]:
        host = (event.metadata.get("host")
                or event.metadata.get("sni")
                or event.metadata.get("dns_query"))

        if host:
            category = get_ai_category(host)
            if category:
                return True, "HIGH", f"Known AI Service [{category}] Accessed: {host}"

        return False, None, None


class UnusualPortDetector(DetectionPlugin):
    """Detects outbound traffic on non-standard ports."""

    name = "Unusual Port Detector"
    description = "Flags internal→external traffic on non-standard ports"

    KNOWN_PORTS = {80, 443, 8080, 53, 8443, 993, 995, 587, 465, 22, 3389}
    INTERNAL_PREFIXES = ["192.168.", "10.0.", "172.16.", "127.0."]

    def detect(self, event: NetworkFlowEvent) -> Tuple[bool, Optional[str], Optional[str]]:
        src_internal = any(event.source_ip.startswith(p) for p in self.INTERNAL_PREFIXES)
        dst_internal = any(event.destination_ip.startswith(p) for p in self.INTERNAL_PREFIXES)

        if src_internal and not dst_internal:
            if event.destination_port not in self.KNOWN_PORTS:
                return (True, "MEDIUM",
                        f"Outbound traffic to {event.destination_ip} on unusual port {event.destination_port}")

        return False, None, None


class DNSTunnelingDetector(DetectionPlugin):
    """Detects potential DNS tunneling based on payload size."""

    name = "DNS Tunneling Detector"
    description = "Flags DNS queries with suspiciously large payloads"

    def detect(self, event: NetworkFlowEvent) -> Tuple[bool, Optional[str], Optional[str]]:
        if event.protocol == Protocol.DNS and event.bytes_sent > 500:
            return True, "HIGH", "Potential DNS Tunneling (Large DNS Payload)"

        return False, None, None


class DataExfiltrationDetector(DetectionPlugin):
    """Detects potential data exfiltration based on upload volume."""

    name = "Data Exfiltration Detector"
    description = "Flags unusually large outbound data transfers to external hosts"

    INTERNAL_PREFIXES = ["192.168.", "10.0.", "172.16.", "127.0."]
    EXFIL_THRESHOLD = 500000  # 500KB in a single flow

    def detect(self, event: NetworkFlowEvent) -> Tuple[bool, Optional[str], Optional[str]]:
        src_internal = any(event.source_ip.startswith(p) for p in self.INTERNAL_PREFIXES)
        dst_internal = any(event.destination_ip.startswith(p) for p in self.INTERNAL_PREFIXES)

        if src_internal and not dst_internal and event.bytes_sent > self.EXFIL_THRESHOLD:
            size_kb = event.bytes_sent / 1024
            return (True, "HIGH",
                    f"Large upload ({size_kb:.0f} KB) to external host {event.destination_ip}")

        return False, None, None
