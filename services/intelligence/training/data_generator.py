"""
Training Data Generator — Creates labeled synthetic data for model training.

Generates realistic traffic samples with known labels so we can train
the classifier without needing weeks of real captured data.
"""
import random
import numpy as np
from datetime import datetime
from typing import List, Tuple
from loguru import logger

from pkg.models.events import NetworkFlowEvent, Protocol
from pkg.data.ai_domains import AI_DOMAINS
from services.intelligence.features.extractor import FeatureExtractor


# Normal browsing destinations
NORMAL_SITES = [
    "google.com", "github.com", "stackoverflow.com", "youtube.com",
    "slack.com", "zoom.us", "figma.com", "notion.so", "jira.atlassian.com",
    "docs.google.com", "mail.google.com", "calendar.google.com",
    "npmjs.com", "pypi.org", "medium.com", "reddit.com",
    "developer.mozilla.org", "aws.amazon.com", "azure.microsoft.com",
]

INTERNAL_IPS = [f"192.168.1.{i}" for i in range(10, 20)]
INTERNAL_SERVERS = ["192.168.1.100", "192.168.1.101", "192.168.1.102", "192.168.1.200"]


class TrainingDataGenerator:
    """Generate labeled synthetic traffic data for training models."""

    def __init__(self):
        self.extractor = FeatureExtractor()

    def generate(self, n_samples: int = 5000, ai_ratio: float = 0.15,
                 suspicious_ratio: float = 0.10) -> Tuple[np.ndarray, List[str]]:
        """
        Generate labeled training data.
        
        Args:
            n_samples: Total samples to generate
            ai_ratio: Fraction that are shadow_ai
            suspicious_ratio: Fraction that are suspicious
            
        Returns:
            (X, y) — Feature matrix and label list
        """
        n_ai = int(n_samples * ai_ratio)
        n_suspicious = int(n_samples * suspicious_ratio)
        n_normal = n_samples - n_ai - n_suspicious

        events = []
        labels = []

        # Normal traffic
        for _ in range(n_normal):
            events.append(self._gen_normal())
            labels.append("normal")

        # Suspicious traffic
        for _ in range(n_suspicious):
            events.append(self._gen_suspicious())
            labels.append("suspicious")

        # Shadow AI traffic
        for _ in range(n_ai):
            events.append(self._gen_shadow_ai())
            labels.append("shadow_ai")

        # Shuffle
        combined = list(zip(events, labels))
        random.shuffle(combined)
        events, labels = zip(*combined)

        X = self.extractor.extract_batch(list(events))
        logger.info(f"Generated {n_samples} training samples: "
                    f"{n_normal} normal, {n_suspicious} suspicious, {n_ai} shadow_ai")
        return X, list(labels)

    def _gen_normal(self) -> NetworkFlowEvent:
        """Generate a normal browsing flow."""
        is_internal = random.random() < 0.3
        if is_internal:
            dst_ip = random.choice(INTERNAL_SERVERS)
            dst_port = random.choice([22, 445, 5432, 8080])
            proto = Protocol.TCP
            host = ""
        else:
            dst_ip = "1.1.1.1"
            dst_port = 443
            proto = Protocol.HTTPS
            host = random.choice(NORMAL_SITES)

        return NetworkFlowEvent(
            source_ip=random.choice(INTERNAL_IPS),
            source_port=random.randint(49152, 65535),
            destination_ip=dst_ip,
            destination_port=dst_port,
            protocol=proto,
            bytes_sent=random.randint(100, 5000),
            bytes_received=random.randint(1000, 50000),
            metadata={"host": host} if host else {},
        )

    def _gen_suspicious(self) -> NetworkFlowEvent:
        """Generate suspicious traffic (unusual ports, high volume)."""
        return NetworkFlowEvent(
            source_ip=random.choice(INTERNAL_IPS),
            source_port=random.randint(49152, 65535),
            destination_ip=f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}",
            destination_port=random.choice([4444, 8888, 9999, 1337, 31337, 6667]),
            protocol=Protocol.TCP,
            bytes_sent=random.randint(10000, 100000),
            bytes_received=random.randint(500, 5000),
            metadata={},
        )

    def _gen_shadow_ai(self) -> NetworkFlowEvent:
        """Generate Shadow AI traffic (known AI domains, large payloads)."""
        ai_domain = random.choice(list(AI_DOMAINS)[:20])
        return NetworkFlowEvent(
            source_ip=random.choice(INTERNAL_IPS),
            source_port=random.randint(49152, 65535),
            destination_ip="8.8.8.8",
            destination_port=443,
            protocol=Protocol.HTTPS,
            bytes_sent=random.randint(5000, 100000),   # Big prompts
            bytes_received=random.randint(10000, 500000),  # Big responses
            metadata={"host": ai_domain, "sni": ai_domain},
        )
