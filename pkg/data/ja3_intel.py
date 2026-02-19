"""
JA3 Fingerprint Intelligence — Client identity verification via TLS handshake.

JA3 is an MD5 hash of the TLS Client Hello fields:
    TLSVersion, Ciphers, Extensions, EllipticCurves, EllipticCurvePointFormats

Different TLS clients (Chrome, Firefox, Python requests, curl, Tor) produce
distinct JA3 hashes, even when they claim the same User-Agent header.
This module provides a database of known fingerprints and a matcher class to
detect identity spoofing and known attack tools.

Usage:
    matcher = JA3Matcher()
    result = matcher.lookup("e7d705a3286e19ea42f587b344ee6865")
    if result:
        print(f"Identified: {result.client_name} ({result.category})")

References:
    - https://engineering.salesforce.com/tls-fingerprinting-with-ja3-and-ja3s/
    - https://ja3er.com/
"""
from dataclasses import dataclass, field
from typing import Optional, List, Dict


@dataclass
class JA3Match:
    """Result of a successful JA3 fingerprint match."""
    ja3_hash: str
    client_name: str          # e.g., "Python requests 2.x", "Chrome 120+"
    category: str             # "browser", "scripting", "attack_tool", "bot", "proxy"
    risk_level: str           # "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"
    description: str          # Human-readable explanation
    expected_ua_patterns: list = field(default_factory=list)  # UA strings this client should have
    tags: list = field(default_factory=list)  # ["spoofing_risk", "known_malware", "automation"]


# ══════════════════════════════════════════════════════════════════════
# JA3 Fingerprint Database — Known Client Signatures
#
# Sources:
#   - ja3er.com community database
#   - Salesforce open-source JA3 research
#   - MITRE ATT&CK T1071 (Application Layer Protocol)
#
# Categories:
#   browser      — Legitimate web browsers
#   scripting    — Programming language HTTP clients
#   attack_tool  — Known offensive security / hacking tools
#   bot          — Automated crawlers and scanners
#   proxy        — VPN, Tor, and proxy software
# ══════════════════════════════════════════════════════════════════════

JA3_DATABASE: List[Dict] = [
    # ── Scripting Languages (High Spoofing Risk) ──────────────────────
    {
        "ja3_hash": "e7d705a3286e19ea42f587b344ee6865",
        "client_name": "Python requests 2.x (urllib3)",
        "category": "scripting",
        "risk_level": "HIGH",
        "description": "Standard Python HTTP client — commonly used for API automation and data exfiltration scripts",
        "expected_ua_patterns": ["python-requests", "python-urllib3"],
        "tags": ["spoofing_risk", "automation"],
    },
    {
        "ja3_hash": "b32309a26951912be7dba376398abc3b",
        "client_name": "Python aiohttp",
        "category": "scripting",
        "risk_level": "HIGH",
        "description": "Async Python HTTP client — used in high-throughput scraping and C2 frameworks",
        "expected_ua_patterns": ["aiohttp", "python"],
        "tags": ["spoofing_risk", "automation", "async"],
    },
    {
        "ja3_hash": "282149a96f83e5e4e0b2c26c3c4efc43",
        "client_name": "Python httpx",
        "category": "scripting",
        "risk_level": "HIGH",
        "description": "Modern Python HTTP client — used as requests replacement in newer tooling",
        "expected_ua_patterns": ["python-httpx", "python"],
        "tags": ["spoofing_risk", "automation"],
    },
    {
        "ja3_hash": "3b5074b1b5d032e5620f69f9f700ff0e",
        "client_name": "Node.js (https module)",
        "category": "scripting",
        "risk_level": "MEDIUM",
        "description": "Node.js native HTTPS — used in both legitimate services and attack tooling",
        "expected_ua_patterns": ["node", "axios", "got"],
        "tags": ["spoofing_risk"],
    },
    {
        "ja3_hash": "d7a7a67e6a706ba3a3b8ce2e36c2a8e3",
        "client_name": "Go net/http",
        "category": "scripting",
        "risk_level": "MEDIUM",
        "description": "Go standard HTTP client — common in microservices and cloud-native tooling",
        "expected_ua_patterns": ["Go-http-client", "go"],
        "tags": ["spoofing_risk"],
    },

    # ── Attack Tools (Critical) ───────────────────────────────────────
    {
        "ja3_hash": "51c64c77e60f3980eea90869b68c58a8",
        "client_name": "Cobalt Strike Beacon",
        "category": "attack_tool",
        "risk_level": "CRITICAL",
        "description": "Post-exploitation C2 framework — immediate incident response required",
        "expected_ua_patterns": [],
        "tags": ["known_malware", "c2", "apt"],
    },
    {
        "ja3_hash": "72a589da586844d7f0818ce684948eea",
        "client_name": "Metasploit Framework",
        "category": "attack_tool",
        "risk_level": "CRITICAL",
        "description": "Penetration testing framework — may indicate active exploitation",
        "expected_ua_patterns": [],
        "tags": ["known_malware", "exploit"],
    },
    {
        "ja3_hash": "a0e9f5d64349fb13191bc781f81f42e1",
        "client_name": "Mimikatz / Impacket",
        "category": "attack_tool",
        "risk_level": "CRITICAL",
        "description": "Credential theft tooling — lateral movement in progress",
        "expected_ua_patterns": [],
        "tags": ["known_malware", "credential_theft", "lateral_movement"],
    },

    # ── Command-Line Tools ────────────────────────────────────────────
    {
        "ja3_hash": "456523fc94726331a4d5a2e1d40b2cd7",
        "client_name": "curl",
        "category": "scripting",
        "risk_level": "MEDIUM",
        "description": "Command-line HTTP client — commonly used for API interaction and testing",
        "expected_ua_patterns": ["curl"],
        "tags": ["spoofing_risk", "cli"],
    },
    {
        "ja3_hash": "9e10692f1b7f78228b2d4e424db3a98c",
        "client_name": "wget",
        "category": "scripting",
        "risk_level": "MEDIUM",
        "description": "Command-line download tool — may indicate staged payload delivery",
        "expected_ua_patterns": ["Wget"],
        "tags": ["spoofing_risk", "cli"],
    },

    # ── Proxy / Anonymization ─────────────────────────────────────────
    {
        "ja3_hash": "e7d70f5df5e3ddf3d1af4b1a0a38a3a1",
        "client_name": "Tor Browser",
        "category": "proxy",
        "risk_level": "HIGH",
        "description": "Tor network browser — traffic anonymization, may hide exfiltration",
        "expected_ua_patterns": ["Mozilla"],
        "tags": ["anonymization", "evasion"],
    },

    # ── Bots & Scanners ───────────────────────────────────────────────
    {
        "ja3_hash": "b386946a5a44d1ddcc843bc75336dfce",
        "client_name": "Scrapy Spider",
        "category": "bot",
        "risk_level": "MEDIUM",
        "description": "Python web scraping framework — automated data collection",
        "expected_ua_patterns": ["Scrapy"],
        "tags": ["automation", "scraping"],
    },
    {
        "ja3_hash": "19e29534fd49dd27d09234e639c4057e",
        "client_name": "Headless Chrome (Puppeteer)",
        "category": "bot",
        "risk_level": "HIGH",
        "description": "Headless browser automation — may bypass bot detection while scraping",
        "expected_ua_patterns": ["HeadlessChrome", "Chrome"],
        "tags": ["automation", "headless", "spoofing_risk"],
    },
    {
        "ja3_hash": "cd08e31494816f6d2f3d8a2d0c4ab314",
        "client_name": "Selenium WebDriver",
        "category": "bot",
        "risk_level": "HIGH",
        "description": "Browser automation framework — UI testing or credential stuffing",
        "expected_ua_patterns": ["Chrome", "Firefox"],
        "tags": ["automation", "spoofing_risk"],
    },

    # ── Legitimate Browsers (Baseline — INFO level) ───────────────────
    {
        "ja3_hash": "773906b0efdefa24a7f2b8eb6985bf37",
        "client_name": "Chrome 120+",
        "category": "browser",
        "risk_level": "INFO",
        "description": "Standard Google Chrome browser — expected enterprise traffic",
        "expected_ua_patterns": ["Chrome", "Mozilla"],
        "tags": ["legitimate"],
    },
    {
        "ja3_hash": "579ccef312d18482fc42e2b822ca2430",
        "client_name": "Firefox 120+",
        "category": "browser",
        "risk_level": "INFO",
        "description": "Standard Mozilla Firefox browser — expected enterprise traffic",
        "expected_ua_patterns": ["Firefox", "Mozilla"],
        "tags": ["legitimate"],
    },
    {
        "ja3_hash": "b20b44b18b853f29d25660b022eb7350",
        "client_name": "Edge 120+",
        "category": "browser",
        "risk_level": "INFO",
        "description": "Microsoft Edge browser — expected enterprise traffic (Chromium-based)",
        "expected_ua_patterns": ["Edg", "Chrome", "Mozilla"],
        "tags": ["legitimate"],
    },
    {
        "ja3_hash": "a441a33aaee795f498d6b764cc78989a",
        "client_name": "Safari 17+",
        "category": "browser",
        "risk_level": "INFO",
        "description": "Apple Safari browser — macOS/iOS traffic",
        "expected_ua_patterns": ["Safari", "AppleWebKit"],
        "tags": ["legitimate"],
    },
]


class JA3Matcher:
    """
    High-performance JA3 fingerprint matcher.

    Pre-indexes all fingerprints into a hash map at init time for O(1) lookup.
    Also provides User-Agent mismatch detection for spoofing analysis.
    """

    def __init__(self):
        self._index: Dict[str, Dict] = {}
        for entry in JA3_DATABASE:
            self._index[entry["ja3_hash"]] = entry

    def lookup(self, ja3_hash: str) -> Optional[JA3Match]:
        """
        Look up a JA3 hash against the known fingerprint database.

        Args:
            ja3_hash: MD5 hash string (32 hex characters)

        Returns:
            JA3Match if the fingerprint is known, None otherwise
        """
        if not ja3_hash or len(ja3_hash) != 32:
            return None

        entry = self._index.get(ja3_hash)
        if entry:
            return JA3Match(
                ja3_hash=entry["ja3_hash"],
                client_name=entry["client_name"],
                category=entry["category"],
                risk_level=entry["risk_level"],
                description=entry["description"],
                expected_ua_patterns=entry.get("expected_ua_patterns", []),
                tags=entry.get("tags", []),
            )
        return None

    def detect_spoofing(self, ja3_hash: str, user_agent: str) -> Optional[Dict]:
        """
        Detect User-Agent / JA3 mismatch (identity spoofing).

        A script claiming to be "Chrome" via its User-Agent header but with
        a Python JA3 fingerprint is a classic evasion technique.

        Args:
            ja3_hash: The JA3 fingerprint from the TLS Client Hello
            user_agent: The User-Agent header string from the HTTP request

        Returns:
            Dict with spoofing details if mismatch detected, None otherwise
        """
        match = self.lookup(ja3_hash)
        if not match or not user_agent:
            return None

        # Skip browsers — their UA is expected to match
        if match.category == "browser":
            return None

        # Check if the User-Agent pretends to be something else
        ua_lower = user_agent.lower()
        browser_indicators = ["chrome", "firefox", "safari", "edge", "mozilla"]

        claims_browser = any(indicator in ua_lower for indicator in browser_indicators)
        is_not_browser = match.category in ("scripting", "attack_tool", "bot", "proxy")

        if claims_browser and is_not_browser:
            # Check if ANY expected UA pattern matches (some tools do use Mozilla prefixes)
            expected_match = any(
                pat.lower() in ua_lower for pat in match.expected_ua_patterns
            )
            # If the expected patterns DON'T include browser strings, this is spoofing
            expected_has_browser = any(
                b in pat.lower()
                for pat in match.expected_ua_patterns
                for b in browser_indicators
            )

            if not expected_has_browser:
                return {
                    "spoofing_detected": True,
                    "ja3_client": match.client_name,
                    "ja3_category": match.category,
                    "claimed_ua": user_agent[:100],  # Truncate for safety
                    "risk_level": "CRITICAL",
                    "description": (
                        f"Identity spoofing: TLS fingerprint identifies {match.client_name} "
                        f"but User-Agent claims to be a browser"
                    ),
                }

        return None

    def is_known_bad(self, ja3_hash: str) -> bool:
        """Quick check if a JA3 hash belongs to a known attack tool."""
        match = self.lookup(ja3_hash)
        return match is not None and match.category == "attack_tool"

    def get_all_fingerprints(self) -> List[Dict]:
        """Get a summary of all tracked fingerprints for API/dashboard exposure."""
        return [
            {
                "ja3_hash": e["ja3_hash"],
                "client_name": e["client_name"],
                "category": e["category"],
                "risk_level": e["risk_level"],
            }
            for e in JA3_DATABASE
        ]

    @property
    def total_fingerprints(self) -> int:
        """Total number of fingerprints in the database."""
        return len(self._index)
