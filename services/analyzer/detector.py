"""
Anomaly Detector — Plugin-based detection engine.

Dynamically loads all DetectionPlugin implementations from the plugins/ directory.
Also maintains the whitelist to suppress false positives.
"""
import os
import importlib
import inspect
from typing import Tuple, Optional, List
from loguru import logger

from pkg.models.events import NetworkFlowEvent
from services.analyzer.plugin_base import DetectionPlugin


class AnomalyDetector:
    """
    Detects Shadow AI and Anomalous behaviors using a plugin architecture.
    Includes whitelisting to reduce false positives.
    """

    def __init__(self):
        self.known_subnets = ["192.168.", "10.0.", "172.16.", "127.0."]
        self.plugins: List[DetectionPlugin] = []

        # Whitelisted patterns — known safe, suppress alerts
        self.whitelist_ips = {
            "224.0.0.251", "224.0.0.252", "239.255.255.250",
            "255.255.255.255", "224.0.0.1", "224.0.0.2",
        }
        self.whitelist_prefixes = ["224.", "239.", "fe80:", "ff02:"]
        self.whitelist_ports = {5353, 1900, 5228, 5229, 5230}

        # Auto-load plugins
        self._load_plugins()

    def _load_plugins(self):
        """Discover and load all DetectionPlugin subclasses from plugins/ dir."""
        plugins_dir = os.path.join(os.path.dirname(__file__), "plugins")

        if not os.path.isdir(plugins_dir):
            logger.warning(f"Plugins directory not found: {plugins_dir}")
            return

        for filename in sorted(os.listdir(plugins_dir)):
            if filename.startswith("_") or not filename.endswith(".py"):
                continue

            module_name = f"services.analyzer.plugins.{filename[:-3]}"
            try:
                module = importlib.import_module(module_name)
                for attr_name in dir(module):
                    attr = getattr(module, attr_name)
                    if (inspect.isclass(attr)
                            and issubclass(attr, DetectionPlugin)
                            and attr is not DetectionPlugin
                            and attr.enabled):
                        plugin = attr()
                        self.plugins.append(plugin)
                        logger.info(f"  🔌 Loaded plugin: {plugin.name}")
            except Exception as e:
                logger.error(f"Failed to load plugin {filename}: {e}")

        logger.info(f"Plugin system: {len(self.plugins)} detection plugins active")

    def is_internal(self, ip: str) -> bool:
        return any(ip.startswith(prefix) for prefix in self.known_subnets)

    def is_whitelisted(self, event: NetworkFlowEvent) -> bool:
        """Check if this traffic matches a known safe pattern."""
        dst = event.destination_ip

        if dst in self.whitelist_ips:
            return True
        if any(dst.startswith(p) for p in self.whitelist_prefixes):
            return True
        if event.destination_port in self.whitelist_ports:
            return True
        if self.is_internal(event.source_ip) and self.is_internal(dst):
            return True

        return False

    def detect(self, event: NetworkFlowEvent) -> Tuple[bool, Optional[str]]:
        """
        Run all plugins against the event.
        Returns (is_anomalous, reason) — uses the highest-severity match.
        """
        # Skip whitelisted patterns
        if self.is_whitelisted(event):
            return False, None

        # Run all plugins, collect hits
        severity_rank = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}
        best_hit = None

        for plugin in self.plugins:
            try:
                is_anomalous, severity, reason = plugin.detect(event)
                if is_anomalous and severity:
                    rank = severity_rank.get(severity, 0)
                    if best_hit is None or rank > best_hit[0]:
                        best_hit = (rank, severity, reason)
            except Exception as e:
                logger.error(f"Plugin {plugin.name} error: {e}")

        if best_hit:
            return True, best_hit[2]

        return False, None
