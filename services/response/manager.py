"""
Auto-Response Manager (SOAR) — Automated blocking for critical threats.

Simulates firewall integration to quarantine IPs that trigger CRITICAL-severity
alerts (risk score > 0.95). In production, this would interface with actual
firewall APIs (iptables, AWS Security Groups, Palo Alto, etc.).

Current implementation:
    - Maintains an in-memory blocklist of quarantined IPs.
    - Provides block_ip / unblock_ip operations with audit logging.
    - Supports a whitelist to prevent accidental blocking of infrastructure.
    - Exposes an API-ready summary for dashboard integration.

Safety:
    - Whitelist prevents blocking of DNS, gateways, and other infra.
    - Auto-block has a maximum list size to prevent runaway blocking.
    - All block/unblock actions are logged with timestamps and reasons.
"""
import time
from typing import Dict, List, Optional, Set
from dataclasses import dataclass, field
from loguru import logger


@dataclass
class BlockEntry:
    """Record of a blocked IP address."""
    ip: str
    reason: str
    severity: str
    timestamp: float
    source_alert_id: Optional[str] = None
    auto_blocked: bool = True
    expires_at: Optional[float] = None     # TTL for auto-expiry (None = permanent)


# IPs that must NEVER be blocked, regardless of alert severity.
BLOCK_WHITELIST = {
    # DNS servers
    "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1",
    # Default gateways
    "192.168.1.1", "192.168.0.1", "10.0.0.1",
    # Broadcast/multicast
    "255.255.255.255", "224.0.0.1", "224.0.0.251",
}


class ResponseManager:
    """
    Automated response system for high-risk threats.

    Simulates firewall blocking — maintains a blocklist of quarantined IPs
    with full audit trail. In production, extend with real firewall APIs.
    """

    def __init__(
        self,
        max_blocked: int = 500,
        auto_expire_seconds: float = 3600.0,   # 1 hour default TTL
        enabled: bool = True,
    ):
        self.enabled = enabled
        self.max_blocked = max_blocked
        self.auto_expire_seconds = auto_expire_seconds

        self._blocked: Dict[str, BlockEntry] = {}
        self._audit_log: List[Dict] = []
        self._total_blocks: int = 0
        self._total_unblocks: int = 0

        if self.enabled:
            logger.info(
                f"🛡 Auto-Response armed (max={max_blocked}, "
                f"TTL={auto_expire_seconds}s)"
            )

    def _is_whitelisted(self, ip: str) -> bool:
        """Check if an IP is on the never-block whitelist."""
        if ip in BLOCK_WHITELIST:
            return True
        # Never block loopback or multicast
        if ip.startswith("127.") or ip.startswith("224.") or ip.startswith("239."):
            return True
        return False

    def _cleanup_expired(self):
        """Remove expired block entries."""
        now = time.time()
        expired = [
            ip for ip, entry in self._blocked.items()
            if entry.expires_at and entry.expires_at < now
        ]
        for ip in expired:
            self._unblock(ip, "Auto-expired (TTL reached)")

    def _log_action(self, action: str, ip: str, reason: str, auto: bool = True):
        """Record an audit trail entry."""
        entry = {
            "action": action,
            "ip": ip,
            "reason": reason,
            "auto": auto,
            "timestamp": time.time(),
        }
        self._audit_log.append(entry)
        # Keep last 1000 entries
        if len(self._audit_log) > 1000:
            self._audit_log = self._audit_log[-1000:]

    def block_ip(
        self,
        ip: str,
        reason: str,
        severity: str = "CRITICAL",
        alert_id: Optional[str] = None,
        auto: bool = True,
    ) -> Dict:
        """
        Block (quarantine) an IP address.

        Args:
            ip: IP address to block
            reason: Human-readable reason for the block
            severity: Alert severity that triggered the block
            alert_id: ID of the triggering alert
            auto: Whether this was an automatic block

        Returns:
            Dict with block result and status
        """
        # Safety checks
        if not self.enabled:
            return {"blocked": False, "reason": "Auto-Response is disabled"}

        if self._is_whitelisted(ip):
            logger.info(f"🛡 Block rejected: {ip} is whitelisted")
            self._log_action("BLOCK_REJECTED", ip, f"Whitelisted — {reason}", auto)
            return {"blocked": False, "reason": f"{ip} is whitelisted"}

        if ip in self._blocked:
            return {"blocked": False, "reason": f"{ip} is already blocked"}

        # Capacity check
        self._cleanup_expired()
        if len(self._blocked) >= self.max_blocked:
            logger.warning(f"🛡 Block list full ({self.max_blocked}) — cannot block {ip}")
            return {"blocked": False, "reason": "Block list capacity reached"}

        # Block the IP
        entry = BlockEntry(
            ip=ip,
            reason=reason,
            severity=severity,
            timestamp=time.time(),
            source_alert_id=alert_id,
            auto_blocked=auto,
            expires_at=time.time() + self.auto_expire_seconds if auto else None,
        )
        self._blocked[ip] = entry
        self._total_blocks += 1

        self._log_action("BLOCKED", ip, reason, auto)
        logger.warning(
            f"🛡 IP BLOCKED: {ip} — {reason} "
            f"(severity={severity}, auto={auto}, "
            f"expires={'in ' + str(int(self.auto_expire_seconds)) + 's' if auto else 'never'})"
        )

        # In production, this is where you'd call:
        # await firewall.add_rule(ip, action="DROP")
        # await security_group.revoke_ingress(ip)

        return {
            "blocked": True,
            "ip": ip,
            "reason": reason,
            "severity": severity,
            "expires_at": entry.expires_at,
            "total_blocked": len(self._blocked),
        }

    def _unblock(self, ip: str, reason: str):
        """Internal unblock (used by expiry and manual unblock)."""
        if ip in self._blocked:
            del self._blocked[ip]
            self._total_unblocks += 1
            self._log_action("UNBLOCKED", ip, reason, auto=True)
            logger.info(f"🛡 IP UNBLOCKED: {ip} — {reason}")

    def unblock_ip(self, ip: str, reason: str = "Manual unblock") -> Dict:
        """
        Manually unblock a previously quarantined IP.

        Args:
            ip: IP address to unblock
            reason: Reason for the unblock

        Returns:
            Dict with unblock result
        """
        if ip not in self._blocked:
            return {"unblocked": False, "reason": f"{ip} is not currently blocked"}

        self._unblock(ip, reason)
        return {"unblocked": True, "ip": ip, "reason": reason}

    def is_blocked(self, ip: str) -> bool:
        """Check if an IP is currently blocked."""
        self._cleanup_expired()
        return ip in self._blocked

    @property
    def blocked_ips(self) -> List[Dict]:
        """Get all currently blocked IPs with their details."""
        self._cleanup_expired()
        return [
            {
                "ip": entry.ip,
                "reason": entry.reason,
                "severity": entry.severity,
                "blocked_at": entry.timestamp,
                "auto_blocked": entry.auto_blocked,
                "expires_at": entry.expires_at,
                "alert_id": entry.source_alert_id,
            }
            for entry in self._blocked.values()
        ]

    @property
    def stats(self) -> Dict:
        """Response system statistics."""
        self._cleanup_expired()
        return {
            "enabled": self.enabled,
            "currently_blocked": len(self._blocked),
            "max_capacity": self.max_blocked,
            "total_blocks": self._total_blocks,
            "total_unblocks": self._total_unblocks,
            "audit_log_size": len(self._audit_log),
        }

    @property
    def recent_audit_log(self) -> List[Dict]:
        """Get the last 50 audit log entries."""
        return self._audit_log[-50:]
