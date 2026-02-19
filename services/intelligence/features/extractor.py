"""
Feature Extractor — Converts raw NetworkFlowEvents into numeric feature vectors
for ML model consumption.

v2: Added flow-context features (time-based) for improved accuracy:
  - hour_of_day: Captures time-based usage patterns (AI usage at odd hours).
  - is_ai_port: Dedicated signal for common AI API ports.
  - payload_entropy_hint: Rough heuristic for compressed/encrypted payloads.
"""
import numpy as np
from typing import Dict, Any, List
from pkg.models.events import NetworkFlowEvent, Protocol
from pkg.data.cidr_threat_intel import CIDRMatcher


# Protocol to numeric mapping
PROTOCOL_MAP = {
    Protocol.TCP: 0,
    Protocol.UDP: 1,
    Protocol.HTTP: 2,
    Protocol.HTTPS: 3,
    Protocol.DNS: 4,
}

# Well-known port categories
PORT_CATEGORIES = {
    "web": [80, 443, 8080, 8443],
    "mail": [25, 465, 587, 993, 995],
    "dns": [53],
    "ssh": [22],
    "database": [3306, 5432, 27017, 6379],
    "file_transfer": [20, 21, 445],
}

# Ports commonly used by AI APIs and services
AI_API_PORTS = {443, 8080, 8443, 3000, 5000, 8000}


class FeatureExtractor:
    """
    Extracts a fixed-size numeric feature vector from a NetworkFlowEvent.

    Feature Vector (16 dimensions):
    [0]  protocol_id          — Protocol enum as int
    [1]  dst_port_norm         — Destination port (normalized 0-1)
    [2]  bytes_sent_log        — Bytes sent (log-scaled)
    [3]  bytes_received_log    — Bytes received (log-scaled)
    [4]  byte_ratio            — sent / (sent + received) ratio
    [5]  is_internal_src       — 1 if source is internal (RFC1918)
    [6]  is_internal_dst       — 1 if destination is internal
    [7]  is_well_known_port    — 1 if dst port is well-known
    [8]  port_category         — Port category id
    [9]  has_hostname          — 1 if DPI extracted a hostname
    [10] hostname_length       — Length of hostname (0 if none)
    [11] hostname_dot_count    — Number of dots in hostname (subdomain depth)
    [12] hour_of_day           — Hour of packet capture (0-1 normalized)
    [13] is_ai_port            — 1 if destination port is common for AI APIs
    [14] payload_size_bucket   — Categorical bucket for payload size
    [15] is_known_ai_cidr      — 1 if destination IP is in a known AI CIDR block
    """

    FEATURE_NAMES = [
        "protocol_id", "dst_port_norm", "bytes_sent_log", "bytes_received_log",
        "byte_ratio", "is_internal_src", "is_internal_dst", "is_well_known_port",
        "port_category", "has_hostname", "hostname_length", "hostname_dot_count",
        "hour_of_day", "is_ai_port", "payload_size_bucket", "is_known_ai_cidr",
    ]

    INTERNAL_PREFIXES = ["192.168.", "10.", "172.16.", "172.17.", "172.18.",
                         "172.19.", "172.20.", "172.21.", "172.22.", "172.23.",
                         "172.24.", "172.25.", "172.26.", "172.27.", "172.28.",
                         "172.29.", "172.30.", "172.31.", "127."]

    # Shared CIDR matcher instance (singleton-like for efficiency)
    _cidr_matcher = CIDRMatcher()

    def extract(self, event: NetworkFlowEvent) -> np.ndarray:
        """Convert a single flow event to a feature vector."""
        host = event.metadata.get("host") or event.metadata.get("sni") or ""
        total_bytes = event.bytes_sent + event.bytes_received

        features = [
            PROTOCOL_MAP.get(event.protocol, -1),
            event.destination_port / 65535.0,
            np.log1p(event.bytes_sent),
            np.log1p(event.bytes_received),
            event.bytes_sent / max(total_bytes, 1),
            1.0 if self._is_internal(event.source_ip) else 0.0,
            1.0 if self._is_internal(event.destination_ip) else 0.0,
            1.0 if self._is_well_known_port(event.destination_port) else 0.0,
            self._port_category(event.destination_port),
            1.0 if host else 0.0,
            len(host) / 100.0,
            host.count("."),
            # ── Flow-context features ──
            event.timestamp.hour / 23.0,                                      # [12]
            1.0 if event.destination_port in AI_API_PORTS else 0.0,           # [13]
            self._payload_bucket(total_bytes),                                # [14]
            # ── CIDR Threat Intel feature ──
            1.0 if self._cidr_matcher.lookup(event.destination_ip) else 0.0,  # [15]
        ]

        return np.array(features, dtype=np.float32)

    def extract_batch(self, events: List[NetworkFlowEvent]) -> np.ndarray:
        """Convert a list of events to a feature matrix (N x 15)."""
        return np.array([self.extract(e) for e in events], dtype=np.float32)

    def _is_internal(self, ip: str) -> bool:
        return any(ip.startswith(p) for p in self.INTERNAL_PREFIXES)

    def _is_well_known_port(self, port: int) -> bool:
        for ports in PORT_CATEGORIES.values():
            if port in ports:
                return True
        return False

    def _port_category(self, port: int) -> float:
        for i, (_, ports) in enumerate(PORT_CATEGORIES.items()):
            if port in ports:
                return (i + 1) / len(PORT_CATEGORIES)
        return 0.0

    @staticmethod
    def _payload_bucket(total_bytes: int) -> float:
        """
        Categorize payload size into buckets.
        Tiny(0) < 1KB | Small(1) < 10KB | Medium(2) < 100KB | Large(3) < 1MB | Huge(4)
        """
        if total_bytes < 1024:
            return 0.0
        elif total_bytes < 10240:
            return 0.25
        elif total_bytes < 102400:
            return 0.5
        elif total_bytes < 1048576:
            return 0.75
        else:
            return 1.0
