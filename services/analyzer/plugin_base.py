"""
Detection Plugin Interface — Base class for all detection plugins.

Any Python file in the `plugins/` directory that defines a class inheriting
from `DetectionPlugin` will be automatically loaded by the AnalyzerEngine.

Example:
    class MyCustomDetector(DetectionPlugin):
        name = "Custom Detector"
        description = "Detects traffic to my custom blocklist"

        def detect(self, event):
            if event.destination_ip in MY_BLOCKLIST:
                return True, "HIGH", "Matched custom blocklist"
            return False, None, None
"""
from abc import ABC, abstractmethod
from typing import Tuple, Optional
from pkg.models.events import NetworkFlowEvent


class DetectionPlugin(ABC):
    """Base class for all detection plugins."""

    name: str = "Unnamed Plugin"
    description: str = ""
    enabled: bool = True

    @abstractmethod
    def detect(self, event: NetworkFlowEvent) -> Tuple[bool, Optional[str], Optional[str]]:
        """
        Analyze a network flow event.

        Args:
            event: The network flow event to analyze.

        Returns:
            Tuple of (is_anomalous, severity, reason)
            - is_anomalous: True if this event should trigger an alert
            - severity: "HIGH", "MEDIUM", or "LOW" (None if not anomalous)
            - reason: Human-readable description (None if not anomalous)
        """
        pass
