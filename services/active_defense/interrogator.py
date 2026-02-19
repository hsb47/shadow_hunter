"""
Active Interrogation Service — Probe suspicious destinations to verify their nature.

When the Analyzer Engine encounters a CRITICAL-severity alert, it can dispatch
an Active Probe to confirm whether the destination is actually an AI API,
a known C2 server, or a benign service.

Probe Methods:
    1. HTTP OPTIONS — Check allowed methods, CORS headers, API signatures.
    2. AI Endpoint Probe — Hit common AI API paths (/v1/models, /v1/chat)
       and check for characteristic responses.

Safety Guards:
    - Rate limiting: Max N probes per minute to avoid flooding.
    - Internal IP whitelist: Never probe internal/private IPs.
    - Cooldown per target: Don't re-probe the same host within a window.

⚠ IMPORTANT: This module sends active network requests to external hosts.
   Ensure this aligns with your organization's Rules of Engagement.
"""
import asyncio
import time
import ipaddress
from typing import Dict, Optional, List
from dataclasses import dataclass, field
from loguru import logger

try:
    import httpx
    HTTPX_AVAILABLE = True
except ImportError:
    HTTPX_AVAILABLE = False


@dataclass
class ProbeResult:
    """Result of an active interrogation probe."""
    target: str
    probe_type: str              # "http_options", "ai_endpoint"
    timestamp: float
    success: bool
    status_code: Optional[int] = None
    is_ai_service: bool = False
    ai_indicators: list = field(default_factory=list)
    server_header: Optional[str] = None
    headers_of_interest: dict = field(default_factory=dict)
    error: Optional[str] = None


# Common AI API paths to probe
AI_PROBE_PATHS = [
    "/v1/models",           # OpenAI-compatible APIs
    "/v1/chat/completions", # OpenAI chat
    "/api/generate",        # Ollama
    "/api/tags",            # Ollama model list
    "/v1/complete",         # Anthropic
]

# Headers that indicate an AI service
AI_RESPONSE_INDICATORS = [
    "openai",
    "anthropic",
    "x-request-id",         # Common in AI APIs
    "x-ratelimit-limit",    # Rate limiting headers
    "cf-ray",               # Cloudflare (many AI services use it)
]


class ActiveProbe:
    """
    Active defense probe — interrogates suspicious destinations.

    Sends controlled, safe HTTP requests to gather intelligence about
    a destination. Results are fed back into the alert for enrichment.
    """

    def __init__(
        self,
        max_probes_per_minute: int = 10,
        cooldown_seconds: float = 300.0,   # 5 min cooldown per target
        timeout_seconds: float = 5.0,
        enabled: bool = True,
    ):
        self.enabled = enabled and HTTPX_AVAILABLE
        self.max_probes_per_minute = max_probes_per_minute
        self.cooldown_seconds = cooldown_seconds
        self.timeout_seconds = timeout_seconds

        # Rate limiting state
        self._probe_timestamps: List[float] = []
        self._cooldown_map: Dict[str, float] = {}  # target -> last_probe_time
        self._probe_results: List[ProbeResult] = []

        if not HTTPX_AVAILABLE:
            logger.warning("⚠ httpx not installed — Active Interrogation disabled. Run: pip install httpx")
        elif self.enabled:
            logger.info(f"🔍 Active Interrogation armed (rate: {max_probes_per_minute}/min, cooldown: {cooldown_seconds}s)")

    def _is_rate_limited(self) -> bool:
        """Check if we've exceeded the probe rate limit."""
        now = time.time()
        # Clean old timestamps (older than 60s)
        self._probe_timestamps = [t for t in self._probe_timestamps if now - t < 60]
        return len(self._probe_timestamps) >= self.max_probes_per_minute

    def _is_on_cooldown(self, target: str) -> bool:
        """Check if a target is still on probe cooldown."""
        last_probe = self._cooldown_map.get(target)
        if last_probe is None:
            return False
        return (time.time() - last_probe) < self.cooldown_seconds

    def _is_internal_ip(self, ip_or_host: str) -> bool:
        """Safety guard: never probe internal/private IP addresses."""
        try:
            addr = ipaddress.ip_address(ip_or_host)
            return addr.is_private or addr.is_loopback or addr.is_reserved
        except ValueError:
            # It's a hostname, not an IP — safe to probe
            return False

    def _can_probe(self, target: str) -> tuple[bool, str]:
        """Pre-flight checks before probing a target."""
        if not self.enabled:
            return False, "Active Interrogation is disabled"
        if self._is_internal_ip(target):
            return False, f"Safety guard: {target} is an internal IP"
        if self._is_rate_limited():
            return False, "Rate limit exceeded"
        if self._is_on_cooldown(target):
            return False, f"Target {target} is on cooldown"
        return True, "OK"

    async def probe_http_options(self, target: str) -> ProbeResult:
        """
        Send an HTTP OPTIONS request to discover server capabilities.

        This is the lightest probe — just checks what methods are allowed
        and inspects response headers for telltale signs.
        """
        can_probe, reason = self._can_probe(target)
        if not can_probe:
            return ProbeResult(
                target=target, probe_type="http_options",
                timestamp=time.time(), success=False, error=reason
            )

        url = f"https://{target}"
        self._probe_timestamps.append(time.time())
        self._cooldown_map[target] = time.time()

        try:
            async with httpx.AsyncClient(
                timeout=self.timeout_seconds,
                verify=False,  # Don't fail on self-signed certs
                follow_redirects=True,
            ) as client:
                response = await client.options(url)

            # Analyze response headers
            headers = dict(response.headers)
            headers_of_interest = {}
            ai_indicators = []

            server = headers.get("server", "")
            if server:
                headers_of_interest["server"] = server

            # Check for API-like headers
            for key in ["x-request-id", "x-ratelimit-limit", "x-ratelimit-remaining",
                        "access-control-allow-methods", "access-control-allow-origin"]:
                if key in headers:
                    headers_of_interest[key] = headers[key]

            # Check for AI service indicators
            all_headers_str = str(headers).lower()
            for indicator in AI_RESPONSE_INDICATORS:
                if indicator in all_headers_str:
                    ai_indicators.append(indicator)

            is_ai = len(ai_indicators) >= 2  # Needs multiple indicators

            result = ProbeResult(
                target=target,
                probe_type="http_options",
                timestamp=time.time(),
                success=True,
                status_code=response.status_code,
                is_ai_service=is_ai,
                ai_indicators=ai_indicators,
                server_header=server,
                headers_of_interest=headers_of_interest,
            )
            self._probe_results.append(result)

            logger.info(
                f"🔍 Probe [{target}] OPTIONS → {response.status_code} "
                f"(AI indicators: {len(ai_indicators)}, server: {server or 'hidden'})"
            )
            return result

        except Exception as e:
            error_msg = f"{type(e).__name__}: {str(e)[:100]}"
            logger.debug(f"🔍 Probe [{target}] OPTIONS failed: {error_msg}")
            return ProbeResult(
                target=target, probe_type="http_options",
                timestamp=time.time(), success=False, error=error_msg
            )

    async def probe_ai_endpoint(self, target: str) -> ProbeResult:
        """
        Probe common AI API endpoints to confirm the destination is an AI service.

        Sends lightweight GET requests to known API paths like /v1/models.
        Does NOT send any data — read-only probing.
        """
        can_probe, reason = self._can_probe(target)
        if not can_probe:
            return ProbeResult(
                target=target, probe_type="ai_endpoint",
                timestamp=time.time(), success=False, error=reason
            )

        self._probe_timestamps.append(time.time())
        self._cooldown_map[target] = time.time()

        ai_indicators = []
        best_status = None
        headers_of_interest = {}

        try:
            async with httpx.AsyncClient(
                timeout=self.timeout_seconds,
                verify=False,
                follow_redirects=True,
            ) as client:
                for path in AI_PROBE_PATHS:
                    try:
                        url = f"https://{target}{path}"
                        response = await client.get(url)
                        best_status = response.status_code

                        # 401/403 on AI paths = API exists but needs auth
                        if response.status_code in (401, 403):
                            ai_indicators.append(f"auth_required:{path}")

                        # 200 with JSON = likely an API
                        elif response.status_code == 200:
                            content_type = response.headers.get("content-type", "")
                            if "json" in content_type:
                                ai_indicators.append(f"json_api:{path}")
                                # Check response body for AI keywords
                                try:
                                    body = response.text[:500].lower()
                                    ai_keywords = ["model", "gpt", "claude", "llama",
                                                   "completion", "embedding", "token"]
                                    for kw in ai_keywords:
                                        if kw in body:
                                            ai_indicators.append(f"keyword:{kw}")
                                except Exception:
                                    pass

                        # Capture interesting headers from any response
                        for key in ["x-request-id", "x-ratelimit-limit", "server"]:
                            val = response.headers.get(key)
                            if val and key not in headers_of_interest:
                                headers_of_interest[key] = val

                    except Exception:
                        continue  # Individual path failure is OK

            is_ai = len(ai_indicators) >= 2
            result = ProbeResult(
                target=target,
                probe_type="ai_endpoint",
                timestamp=time.time(),
                success=True,
                status_code=best_status,
                is_ai_service=is_ai,
                ai_indicators=ai_indicators,
                headers_of_interest=headers_of_interest,
            )
            self._probe_results.append(result)

            logger.info(
                f"🔍 Probe [{target}] AI endpoints → "
                f"{'CONFIRMED AI' if is_ai else 'inconclusive'} "
                f"(indicators: {ai_indicators})"
            )
            return result

        except Exception as e:
            error_msg = f"{type(e).__name__}: {str(e)[:100]}"
            logger.debug(f"🔍 Probe [{target}] AI endpoints failed: {error_msg}")
            return ProbeResult(
                target=target, probe_type="ai_endpoint",
                timestamp=time.time(), success=False, error=error_msg
            )

    async def interrogate(self, target: str) -> Dict:
        """
        Full interrogation sequence: OPTIONS probe → AI endpoint probe.

        Returns a summary dict suitable for embedding in alerts.
        """
        results = {}

        # Step 1: HTTP OPTIONS (lightweight)
        options_result = await self.probe_http_options(target)
        results["options_probe"] = {
            "success": options_result.success,
            "status_code": options_result.status_code,
            "server": options_result.server_header,
            "ai_indicators": options_result.ai_indicators,
        }

        # Step 2: AI endpoint probing (if OPTIONS didn't already confirm)
        if not options_result.is_ai_service:
            ai_result = await self.probe_ai_endpoint(target)
            results["ai_probe"] = {
                "success": ai_result.success,
                "status_code": ai_result.status_code,
                "is_ai_service": ai_result.is_ai_service,
                "ai_indicators": ai_result.ai_indicators,
            }
            results["confirmed_ai"] = ai_result.is_ai_service
        else:
            results["confirmed_ai"] = True
            results["ai_probe"] = {"skipped": True, "reason": "OPTIONS already confirmed AI"}

        results["target"] = target
        results["timestamp"] = time.time()

        return results

    @property
    def recent_probes(self) -> List[ProbeResult]:
        """Get the last 50 probe results for dashboard display."""
        return self._probe_results[-50:]

    @property
    def stats(self) -> Dict:
        """Probe system statistics."""
        return {
            "total_probes": len(self._probe_results),
            "active_cooldowns": sum(
                1 for t in self._cooldown_map.values()
                if (time.time() - t) < self.cooldown_seconds
            ),
            "rate_window_count": len([
                t for t in self._probe_timestamps if (time.time() - t) < 60
            ]),
            "enabled": self.enabled,
        }
