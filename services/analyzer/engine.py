import asyncio
import os
import time
from typing import Dict, Any
from loguru import logger
from pkg.core.interfaces import EventBroker, GraphStore
from pkg.models.events import NetworkFlowEvent
from services.analyzer.detector import AnomalyDetector
from pkg.data.ai_domains import is_ai_domain
from pkg.data.cidr_threat_intel import CIDRMatcher
from pkg.data.ja3_intel import JA3Matcher
from services.active_defense.interrogator import ActiveProbe
from services.graph.analytics import GraphAnalyzer
from services.response.manager import ResponseManager
from services.api.routers.policy import add_alert

# Check if intelligence module models exist
MODELS_DIR = os.path.join(os.path.dirname(__file__), "..", "intelligence", "saved_models")
ML_AVAILABLE = os.path.exists(os.path.join(MODELS_DIR, "classifier_model.joblib"))


class AnalyzerEngine:
    """
    The "Brain" of Shadow Hunter.

    Two analysis modes:
    - Rule-based: AnomalyDetector (always active, fast)
    - ML-powered: IntelligenceEngine (when trained models are available)

    Performance:
    - Graph writes use asyncio.gather for concurrent upserts.
    - Session context is injected into alerts for richer intelligence.
    """
    def __init__(self, broker: EventBroker, graph_store: GraphStore, use_ml: bool = True, active_defense: bool = True):
        self.broker = broker
        self.graph = graph_store
        self.detector = AnomalyDetector()
        self.cidr_matcher = CIDRMatcher()
        self.ja3_matcher = JA3Matcher()
        self.active_probe = ActiveProbe(enabled=active_defense)
        self.graph_analyzer = GraphAnalyzer(graph_store)
        self.response_manager = ResponseManager(enabled=active_defense)
        self._event_count = 0

        # ML Intelligence Engine (optional, enhances rule-based detection)
        self.intel_engine = None
        if use_ml and ML_AVAILABLE:
            try:
                from services.intelligence.engine import IntelligenceEngine
                self.intel_engine = IntelligenceEngine()
                self.intel_engine.load_models()
                logger.info("🧠 ML Intelligence Engine loaded — enhanced detection active")
            except Exception as e:
                logger.warning(f"ML engine unavailable, using rule-based only: {e}")

    async def start(self):
        logger.info("Analyzer Engine starting...")
        await self.broker.subscribe("sh.telemetry.traffic.v1", self.handle_traffic_event)
        mode = "ML + Rules" if self.intel_engine else "Rules Only"
        logger.info(f"Analyzer subscribed ({mode}).")

    async def handle_traffic_event(self, event_data: Any):
        try:
            # 1. Parse Event
            if isinstance(event_data, dict):
                event = NetworkFlowEvent(**event_data)
            elif isinstance(event_data, NetworkFlowEvent):
                event = event_data
            else:
                logger.error(f"Unknown event data type: {type(event_data)}")
                return

            self._event_count += 1
            if self._event_count % 10 == 0:
                logger.info(f"Analyzer processed {self._event_count} events")

            # 2. Enrich & Classify Nodes
            host = event.metadata.get("host") or event.metadata.get("sni") or event.metadata.get("dns_query")

            src_id = event.source_ip
            src_type = "internal" if self.detector.is_internal(src_id) else "external"
            src_props = {
                "label": src_id,
                "type": src_type,
                "last_seen": event.timestamp.isoformat()
            }

            dst_id = event.destination_ip
            dst_label = dst_id
            dst_type = "external"

            if self.detector.is_internal(dst_id):
                dst_type = "internal"

            if host:
                dst_id = host
                dst_label = host
                if is_ai_domain(host):
                    dst_type = "shadow"
                elif not self.detector.is_internal(dst_id):
                     dst_type = "external"

            dst_props = {
                "label": dst_label,
                "type": dst_type,
                "last_seen": event.timestamp.isoformat()
            }

            # 3. Update Graph — concurrent upserts for performance
            protocol_str = event.protocol.value if hasattr(event.protocol, 'value') else str(event.protocol)
            edge_props = {
                "protocol": protocol_str,
                "dst_port": event.destination_port,
                "byte_count": event.bytes_sent + event.bytes_received,
                "last_seen": event.timestamp.isoformat()
            }
            await asyncio.gather(
                self.graph.add_node(src_id, ["Node"], src_props),
                self.graph.add_node(dst_id, ["Node"], dst_props),
            )
            await self.graph.add_edge(src_id, dst_id, "TALKS_TO", edge_props)

            # 4. Detection — Rule-based (always runs)
            is_anomalous, reason = self.detector.detect(event)
            severity = "HIGH"

            # 5. ML Enhancement — Adds confidence + may catch things rules miss
            ml_verdict = None
            if self.intel_engine and not self.detector.is_whitelisted(event):
                ml_verdict = self.intel_engine.analyze(event)

                # ML can override or enhance the rule-based verdict
                if not is_anomalous and ml_verdict["classification"] == "shadow_ai" and ml_verdict["confidence"] > 0.7:
                    is_anomalous = True
                    reason = f"ML detected Shadow AI ({ml_verdict['confidence']:.0%} confidence)"
                    severity = "HIGH"
                elif not is_anomalous and ml_verdict["classification"] == "suspicious" and ml_verdict["confidence"] > 0.8:
                    is_anomalous = True
                    reason = f"ML flagged suspicious traffic ({ml_verdict['confidence']:.0%} confidence)"
                    severity = "MEDIUM"
                elif not is_anomalous and ml_verdict["is_anomalous"]:
                    is_anomalous = True
                    reason = f"Anomaly detected (score: {ml_verdict['anomaly_score']:.2f})"
                    severity = "LOW"

            # 6. Generate Alert
            if is_anomalous:
                logger.warning(f"🚨 ALERT [{severity}]: {src_id} -> {dst_id} ({reason})")

                alert = {
                    "id": f"alert-{event.timestamp.timestamp()}-{self._event_count}",
                    "severity": severity,
                    "description": reason,
                    "source": src_id,
                    "target": dst_label,
                    "timestamp": event.timestamp.isoformat(),
                    "protocol": protocol_str,
                    "source_port": event.source_port,
                    "destination_port": event.destination_port,
                    "bytes_sent": event.bytes_sent,
                    "bytes_received": event.bytes_received,
                    "matched_rule": reason,
                    "destination_ip": event.destination_ip,
                }

                # Add CIDR Threat Intelligence enrichment
                cidr_match = self.cidr_matcher.lookup(event.destination_ip)
                if cidr_match:
                    alert["cidr_match"] = {
                        "provider": cidr_match.provider,
                        "service": cidr_match.service,
                        "risk_level": cidr_match.risk_level,
                        "category": cidr_match.category,
                        "data_risk": cidr_match.data_risk,
                        "compliance_tags": cidr_match.compliance_tags,
                        "cidr": cidr_match.cidr,
                    }

                # Add JA3 Fingerprint Intelligence enrichment
                ja3_hash = event.metadata.get("ja3_hash")
                if ja3_hash:
                    ja3_match = self.ja3_matcher.lookup(ja3_hash)
                    ja3_info = {"ja3_hash": ja3_hash}
                    if ja3_match:
                        ja3_info["client_name"] = ja3_match.client_name
                        ja3_info["category"] = ja3_match.category
                        ja3_info["risk_level"] = ja3_match.risk_level
                        ja3_info["tags"] = ja3_match.tags
                    # Check for spoofing
                    user_agent = event.metadata.get("user_agent", "")
                    if user_agent:
                        spoof = self.ja3_matcher.detect_spoofing(ja3_hash, user_agent)
                        if spoof:
                            ja3_info["spoofing"] = spoof
                            # Escalate severity for spoofing
                            if severity != "CRITICAL":
                                severity = "HIGH"
                                alert["severity"] = severity
                    alert["ja3_intel"] = ja3_info

                # Add ML metadata if available
                if ml_verdict:
                    alert["ml_classification"] = ml_verdict["classification"]
                    alert["ml_confidence"] = ml_verdict["confidence"]
                    alert["ml_risk_score"] = ml_verdict["risk_score"]

                # Add session context for richer alerts
                if self.intel_engine:
                    session_ctx = self.intel_engine.analyze_session(src_id)
                    if session_ctx.get("flags"):
                        alert["session_flags"] = session_ctx["flags"]
                        alert["session_risk"] = session_ctx["risk_score"]
                        alert["exfil_velocity_kbps"] = session_ctx.get("exfil_velocity_kbps", 0.0)
                        # Escalate severity if session shows sustained abuse
                        if session_ctx["risk_score"] > 0.7 and severity != "HIGH":
                            severity = "HIGH"
                            alert["severity"] = severity
                            alert["description"] += f" [Session risk: {session_ctx['risk_score']:.0%}]"

                # Active Interrogation — probe CRITICAL/HIGH external targets
                if severity in ("CRITICAL", "HIGH") and self.active_probe.enabled:
                    probe_target = host or event.destination_ip
                    if probe_target and not self.detector.is_internal(event.destination_ip):
                        try:
                            probe_result = await self.active_probe.interrogate(probe_target)
                            alert["active_probe"] = probe_result
                            if probe_result.get("confirmed_ai"):
                                alert["description"] += " [Active probe CONFIRMED AI service]"
                        except Exception as e:
                            logger.debug(f"Active probe failed for {probe_target}: {e}")

                # Broadcast to connected clients
                from services.api.transceiver import manager
                await manager.broadcast({
                    "type": "alert",
                    "payload": alert
                })

                add_alert(alert)

                # 8. Auto-Response — block CRITICAL threats
                if severity == "CRITICAL" and self.response_manager.enabled:
                    block_result = self.response_manager.block_ip(
                        ip=event.source_ip,
                        reason=reason,
                        severity=severity,
                        alert_id=alert["id"],
                    )
                    if block_result.get("blocked"):
                        alert["auto_response"] = block_result
                        from services.api.transceiver import manager
                        await manager.broadcast({
                            "type": "auto_response",
                            "payload": {
                                "action": "BLOCK",
                                "ip": event.source_ip,
                                "reason": reason,
                                "alert_id": alert["id"],
                            }
                        })

            # 7. Periodic Graph Analytics — lateral movement detection
            if self.graph_analyzer.should_analyze():
                try:
                    bridge_alerts = await self.graph_analyzer.detect_lateral_movement()
                    for ba in bridge_alerts:
                        graph_alert = {
                            "id": f"graph-{ba.node_id}-{int(time.time())}",
                            "severity": "HIGH" if "HIGH RISK" in ba.risk_assessment else "MEDIUM",
                            "description": ba.risk_assessment,
                            "source": ba.node_id,
                            "target": ", ".join(ba.connected_to[:5]),
                            "timestamp": event.timestamp.isoformat(),
                            "matched_rule": "Graph Centrality Analysis",
                            "graph_centrality": {
                                "centrality_score": ba.centrality_score,
                                "connections": ba.connections,
                                "node_type": ba.node_type,
                                "connected_to": ba.connected_to,
                            }
                        }
                        from services.api.transceiver import manager
                        await manager.broadcast({
                            "type": "alert",
                            "payload": graph_alert
                        })
                        add_alert(graph_alert)
                except Exception as e:
                    logger.debug(f"Graph analytics error: {e}")

        except Exception as e:
            logger.error(f"Error handling event: {e}")
