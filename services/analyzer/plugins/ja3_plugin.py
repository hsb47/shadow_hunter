"""
JA3 Fingerprint Detection Plugin — Client identity verification.

Detects two categories of threats via TLS Client Hello fingerprinting:

1. **Identity Spoofing**: User-Agent claims "Chrome" but JA3 fingerprint
   identifies Python, curl, or another scripting tool. This is a classic
   evasion technique used to bypass WAFs and bot detection.

2. **Known Attack Tools**: JA3 matches a known offensive tool like
   Cobalt Strike, Metasploit, or Mimikatz. Immediate alerting.

The sniffer already extracts JA3 hashes into event.metadata['ja3_hash'].
This plugin consumes that data and cross-references it against the
JA3 fingerprint database in pkg/data/ja3_intel.py.

Auto-loaded by the AnomalyDetector's plugin system — zero config needed.
"""
from typing import Tuple, Optional
from pkg.models.events import NetworkFlowEvent
from pkg.data.ja3_intel import JA3Matcher
from services.analyzer.plugin_base import DetectionPlugin


class JA3FingerprintPlugin(DetectionPlugin):
    """Detects identity spoofing and known attack tools via JA3 fingerprinting."""

    name = "JA3 Fingerprint Analyzer"
    description = "Identifies clients via TLS fingerprint — detects spoofing and malware"

    def __init__(self):
        self.matcher = JA3Matcher()

    def detect(self, event: NetworkFlowEvent) -> Tuple[bool, Optional[str], Optional[str]]:
        ja3_hash = event.metadata.get("ja3_hash")
        if not ja3_hash:
            return False, None, None

        user_agent = event.metadata.get("user_agent", "")

        # ── Priority 1: Known Attack Tools (CRITICAL) ─────────────────
        if self.matcher.is_known_bad(ja3_hash):
            match = self.matcher.lookup(ja3_hash)
            reason = (
                f"🔴 ATTACK TOOL DETECTED: {match.client_name} "
                f"(JA3: {ja3_hash[:12]}...) — {match.description}"
            )
            return True, "CRITICAL", reason

        # ── Priority 2: Identity Spoofing (HIGH) ──────────────────────
        if user_agent:
            spoof = self.matcher.detect_spoofing(ja3_hash, user_agent)
            if spoof:
                reason = (
                    f"🎭 IDENTITY SPOOFING: UA claims browser but TLS fingerprint "
                    f"is {spoof['ja3_client']} ({spoof['ja3_category']})"
                )
                return True, "HIGH", reason

        # ── Priority 3: Known Non-Browser Client (MEDIUM) ─────────────
        match = self.matcher.lookup(ja3_hash)
        if match and match.category in ("scripting", "bot", "proxy"):
            reason = (
                f"🔍 Non-browser client: {match.client_name} "
                f"[{match.category}] (JA3: {ja3_hash[:12]}...)"
            )
            return True, "MEDIUM", reason

        return False, None, None
