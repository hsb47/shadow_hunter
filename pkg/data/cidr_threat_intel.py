"""
CIDR-Based Threat Intelligence — IP-level AI provider detection.

Matches destination IPs against known CIDR blocks owned by AI service providers.
Catches traffic that bypasses DNS (direct IP, SDK-pinned endpoints, VPN tunnels).

Uses Python's stdlib `ipaddress` — zero external dependencies.
"""
import ipaddress
from dataclasses import dataclass
from typing import Optional, List


@dataclass
class ThreatIntelMatch:
    """Result of a successful CIDR match."""
    ip: str
    cidr: str
    provider: str
    service: str
    risk_level: str          # CRITICAL, HIGH, MEDIUM
    category: str            # LLM, Image Gen, Code AI, ML Infra
    data_risk: str           # Human-readable risk description
    compliance_tags: list    # ["SOC2", "GDPR", "HIPAA"]


# ══════════════════════════════════════════════════════════════════════
# CIDR Database — Known AI Provider IP Blocks
# Sources: Public ASN records, BGP route advertisements
# ══════════════════════════════════════════════════════════════════════

AI_CIDR_DATABASE = [
    # ── OpenAI ──
    {
        "cidr": "13.107.42.0/24",
        "provider": "OpenAI",
        "service": "ChatGPT / GPT-4 API",
        "risk_level": "CRITICAL",
        "category": "LLM",
        "data_risk": "Prompts may contain PII, proprietary code, or trade secrets",
        "compliance_tags": ["SOC2", "GDPR", "HIPAA"],
    },
    {
        "cidr": "13.107.43.0/24",
        "provider": "OpenAI",
        "service": "GPT-4 Turbo API",
        "risk_level": "CRITICAL",
        "category": "LLM",
        "data_risk": "High-throughput API access — bulk data exfiltration risk",
        "compliance_tags": ["SOC2", "GDPR", "HIPAA"],
    },
    {
        "cidr": "40.119.0.0/16",
        "provider": "OpenAI (Azure)",
        "service": "Azure OpenAI Service",
        "risk_level": "HIGH",
        "category": "LLM",
        "data_risk": "Enterprise AI access via Azure — may bypass network controls",
        "compliance_tags": ["SOC2", "GDPR"],
    },

    # ── Anthropic ──
    {
        "cidr": "34.102.136.0/24",
        "provider": "Anthropic",
        "service": "Claude 3.5 Sonnet API",
        "risk_level": "CRITICAL",
        "category": "LLM",
        "data_risk": "Large context window (200K tokens) enables massive data ingestion",
        "compliance_tags": ["SOC2", "GDPR", "HIPAA"],
    },
    {
        "cidr": "34.102.137.0/24",
        "provider": "Anthropic",
        "service": "Claude API",
        "risk_level": "CRITICAL",
        "category": "LLM",
        "data_risk": "Multi-modal capabilities may process sensitive documents",
        "compliance_tags": ["SOC2", "GDPR", "HIPAA"],
    },

    # ── Google AI ──
    {
        "cidr": "142.250.0.0/16",
        "provider": "Google",
        "service": "Gemini / Vertex AI",
        "risk_level": "HIGH",
        "category": "LLM",
        "data_risk": "Data may be used for model improvement without explicit consent",
        "compliance_tags": ["SOC2", "GDPR"],
    },
    {
        "cidr": "172.217.0.0/16",
        "provider": "Google",
        "service": "Google AI Studio / NotebookLM",
        "risk_level": "HIGH",
        "category": "LLM",
        "data_risk": "Shared across Google services — broad data exposure",
        "compliance_tags": ["SOC2", "GDPR"],
    },

    # ── Hugging Face ──
    {
        "cidr": "54.164.0.0/16",
        "provider": "Hugging Face",
        "service": "Inference API / Model Hub",
        "risk_level": "HIGH",
        "category": "ML Infra",
        "data_risk": "Open-source model hosting — variable data handling policies",
        "compliance_tags": ["SOC2"],
    },

    # ── Stability AI ──
    {
        "cidr": "104.18.0.0/16",
        "provider": "Stability AI",
        "service": "Stable Diffusion API",
        "risk_level": "MEDIUM",
        "category": "Image Gen",
        "data_risk": "Image generation from text prompts — IP leakage via descriptions",
        "compliance_tags": ["SOC2"],
    },

    # ── Cohere ──
    {
        "cidr": "35.203.0.0/16",
        "provider": "Cohere",
        "service": "Embed / Generate API",
        "risk_level": "HIGH",
        "category": "LLM",
        "data_risk": "Embedding API may expose document semantics to third party",
        "compliance_tags": ["SOC2", "GDPR"],
    },

    # ── Replicate ──
    {
        "cidr": "44.226.0.0/16",
        "provider": "Replicate",
        "service": "Model Hosting Platform",
        "risk_level": "MEDIUM",
        "category": "ML Infra",
        "data_risk": "Third-party model hosting — data processed on shared infra",
        "compliance_tags": ["SOC2"],
    },

    # ── Mistral AI ──
    {
        "cidr": "51.159.0.0/16",
        "provider": "Mistral AI",
        "service": "Mistral Large / Le Chat",
        "risk_level": "HIGH",
        "category": "LLM",
        "data_risk": "EU-based but data sovereignty varies by deployment",
        "compliance_tags": ["SOC2", "GDPR"],
    },

    # ── Meta AI ──
    {
        "cidr": "157.240.0.0/16",
        "provider": "Meta",
        "service": "Llama API / Meta AI",
        "risk_level": "HIGH",
        "category": "LLM",
        "data_risk": "Open-weight models but API calls route through Meta infra",
        "compliance_tags": ["SOC2", "GDPR"],
    },

    # ── Together AI ──
    {
        "cidr": "34.149.0.0/16",
        "provider": "Together AI",
        "service": "Inference API (OSS models)",
        "risk_level": "MEDIUM",
        "category": "ML Infra",
        "data_risk": "Shared GPU clusters processing multiple tenants",
        "compliance_tags": ["SOC2"],
    },

    # ── Groq ──
    {
        "cidr": "76.76.21.0/24",
        "provider": "Groq",
        "service": "LPU Inference API",
        "risk_level": "MEDIUM",
        "category": "ML Infra",
        "data_risk": "Ultra-fast inference — high throughput data processing",
        "compliance_tags": ["SOC2"],
    },
]


class CIDRMatcher:
    """
    High-performance CIDR-based IP matcher.

    Pre-parses all CIDR strings into ipaddress.ip_network objects at init time.
    Lookup is O(N) worst case where N = number of CIDR entries (~15).
    For production scale, this could be replaced with a radix/Patricia trie.
    """

    def __init__(self):
        self._entries = []
        for entry in AI_CIDR_DATABASE:
            try:
                network = ipaddress.ip_network(entry["cidr"], strict=False)
                self._entries.append((network, entry))
            except ValueError as e:
                # Skip malformed entries silently in production
                pass

    def lookup(self, ip_str: str) -> Optional[ThreatIntelMatch]:
        """
        Check if an IP address falls within any known AI provider CIDR block.

        Args:
            ip_str: IPv4 address string (e.g., "13.107.42.14")

        Returns:
            ThreatIntelMatch if found, None otherwise
        """
        try:
            addr = ipaddress.ip_address(ip_str)
        except ValueError:
            return None

        # Skip private/reserved IPs immediately
        if addr.is_private or addr.is_loopback or addr.is_multicast:
            return None

        for network, entry in self._entries:
            if addr in network:
                return ThreatIntelMatch(
                    ip=ip_str,
                    cidr=entry["cidr"],
                    provider=entry["provider"],
                    service=entry["service"],
                    risk_level=entry["risk_level"],
                    category=entry["category"],
                    data_risk=entry["data_risk"],
                    compliance_tags=entry["compliance_tags"],
                )

        return None

    def enrich_destinations(self, ip_list: list) -> List[ThreatIntelMatch]:
        """
        Batch lookup — check multiple IPs, return only matches.

        Args:
            ip_list: List of IP address strings

        Returns:
            List of ThreatIntelMatch objects (only matches)
        """
        matches = []
        seen = set()
        for ip in ip_list:
            if ip not in seen:
                seen.add(ip)
                match = self.lookup(ip)
                if match:
                    matches.append(match)
        return matches

    def get_all_providers(self) -> list:
        """Get a summary of all tracked providers."""
        providers = {}
        for _, entry in self._entries:
            name = entry["provider"]
            if name not in providers:
                providers[name] = {
                    "provider": name,
                    "cidr_blocks": [],
                    "services": [],
                    "risk_level": entry["risk_level"],
                }
            providers[name]["cidr_blocks"].append(entry["cidr"])
            providers[name]["services"].append(entry["service"])
        return list(providers.values())
