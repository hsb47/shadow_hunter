from pkg.models.events import NetworkFlowEvent, Protocol
from pkg.data.ai_domains import is_ai_domain

class AnomalyDetector:
    """
    Detects Shadow AI and Anomalous behaviors.
    Includes whitelisting to reduce false positives.
    """
    def __init__(self):
        self.known_subnets = ["192.168.", "10.0.", "172.16.", "127.0."]
        self.known_ports = [80, 443, 8080, 53, 8443, 993, 995, 587, 465, 22, 3389]
        
        # Whitelisted patterns — known safe, suppress alerts
        self.whitelist_ips = {
            # Multicast / Broadcast
            "224.0.0.251",    # mDNS
            "224.0.0.252",    # LLMNR
            "239.255.255.250", # UPnP/SSDP
            "255.255.255.255", # Broadcast
            "224.0.0.1",      # All hosts multicast
            "224.0.0.2",      # All routers multicast
        }
        self.whitelist_prefixes = [
            "224.",           # All multicast
            "239.",           # Administratively scoped multicast
            "fe80:",          # Link-local IPv6
            "ff02:",          # IPv6 multicast
        ]
        self.whitelist_ports = {
            5353,   # mDNS
            1900,   # UPnP/SSDP
            5228,   # Google Play services push
            5229,   # Google Play services
            5230,   # Google Play services
        }

    def is_internal(self, ip: str) -> bool:
        return any(ip.startswith(prefix) for prefix in self.known_subnets)

    def is_whitelisted(self, event: NetworkFlowEvent) -> bool:
        """Check if this traffic matches a known safe pattern."""
        dst = event.destination_ip
        
        # Known safe IPs
        if dst in self.whitelist_ips:
            return True
        
        # Multicast/broadcast prefixes
        if any(dst.startswith(p) for p in self.whitelist_prefixes):
            return True
        
        # Known safe service ports
        if event.destination_port in self.whitelist_ports:
            return True
        
        # Internal-to-internal traffic is always safe
        if self.is_internal(event.source_ip) and self.is_internal(dst):
            return True
        
        return False

    def detect(self, event: NetworkFlowEvent) -> (bool, str):
        """
        Returns (is_anomalous, reason)
        """
        # 0. Skip whitelisted patterns (reduces false positives)
        if self.is_whitelisted(event):
            return False, None

        # 1. Metadata Analysis (DPI)
        host = event.metadata.get("host") or event.metadata.get("sni") or event.metadata.get("dns_query")
        
        if host:
            from pkg.data.ai_domains import get_ai_category
            category = get_ai_category(host)
            if category:
                return True, f"Known AI Service [{category}] Accessed: {host}"
            
            # If it's a domain we don't know, and it's definitely not internal
            if not self.is_internal(host) and not host.endswith(".local") and "." in host:
                 # Shadow Service heuristic
                 pass 

        # 2. Rule: Unknown outbound traffic on non-standard ports
        if self.is_internal(event.source_ip) and not self.is_internal(event.destination_ip):
            if event.destination_port not in self.known_ports:
                return True, f"Outbound traffic to {event.destination_ip} on unusual port {event.destination_port}"

        # 3. Rule: DNS tunneling suspect (High payload size on DNS)
        if event.protocol == Protocol.DNS and event.bytes_sent > 500:
             return True, "Potential DNS Tunneling (Large DNS Payload)"

        return False, None

