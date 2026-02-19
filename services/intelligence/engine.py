"""
Intelligence Engine — Main entry point for ML-powered traffic analysis.

1. Loads trained models (Anomaly & Classifier).
2. Extracts features from real-time NetworkFlowEvents.
3. Returns a verdict (risk score, classification, anomalies).
"""
import os
import joblib
import numpy as np
from loguru import logger
from typing import Dict, Any

from pkg.models.events import NetworkFlowEvent
from services.intelligence.features.extractor import FeatureExtractor
from services.intelligence.models.anomaly import AnomalyModel
from services.intelligence.models.classifier import TrafficClassifier
from services.intelligence.models.sequence import SessionAnalyzer

# Paths
MODEL_DIR = os.path.join(os.path.dirname(__file__), "saved_models")
ANOMALY_PATH = os.path.join(MODEL_DIR, "anomaly_model.joblib")
CLASSIFIER_PATH = os.path.join(MODEL_DIR, "classifier_model.joblib")


class IntelligenceEngine:
    """
    Real-time ML analysis engine.
    
    Usage:
        engine = IntelligenceEngine()
        engine.load_models()
        result = engine.analyze(event)
    """

    def __init__(self):
        self.extractor = FeatureExtractor()
        
        # Models
        self.anomaly_model = AnomalyModel()
        self.classifier = TrafficClassifier()
        self.session_analyzer = SessionAnalyzer(window_minutes=60)
        
        self.models_loaded = False

    def load_models(self):
        """Load trained models from disk."""
        try:
            if os.path.exists(ANOMALY_PATH):
                self.anomaly_model.load(ANOMALY_PATH)
            else:
                logger.warning(f"Anomaly model not found at {ANOMALY_PATH}")

            if os.path.exists(CLASSIFIER_PATH):
                self.classifier.load(CLASSIFIER_PATH)
            else:
                logger.warning(f"Classifier model not found at {CLASSIFIER_PATH}")
                
            self.models_loaded = True
            logger.info("Intelligence Engine models loaded successfully.")
        except Exception as e:
            logger.error(f"Failed to load models: {e}")

    def analyze(self, event: NetworkFlowEvent) -> Dict[str, Any]:
        """
        Analyze a single network flow event.
        
        Returns:
            {
                "is_anomalous": bool,
                "anomaly_score": float,
                "classification": str (normal/suspicious/shadow_ai),
                "confidence": float,
                "risk_score": float,  # 0.0 to 1.0
                "reasons": list[str]
            }
        """
        # 1. Update session history (behavioral analysis)
        self.session_analyzer.record(
            event.source_ip, 
            event.metadata.get("host") or event.destination_ip, 
            "unknown", # we don't know type yet
            event.bytes_sent + event.bytes_received, 
            event.timestamp
        )

        # 2. Extract features
        features = self.extractor.extract(event).reshape(1, -1)
        
        # 3. Anomaly Detection
        anomaly_score = self.anomaly_model.predict(features)[0]
        is_anomalous = anomaly_score < -0.2  # Threshold
        
        # 4. Classification
        classification = "unknown"
        confidence = 0.0
        probas = self.classifier.predict_proba(features)[0]
        
        # Map distinct probabilities to classes
        # [normal, suspicious, shadow_ai]
        # Note: Class order depends on training labels, typically alphabetical
        # We'll use the predicted label string to be safe
        pred_label = self.classifier.predict(features)[0]
        classification = pred_label
        
        # Confidence is the probability of the predicted class
        class_idx = list(self.classifier.label_encoder.classes_).index(pred_label)
        confidence = probas[class_idx]
        
        # 5. Risk Scoring Logic
        risk_score = 0.0
        reasons = []

        if classification == "shadow_ai":
            risk_score = 0.9 if confidence > 0.8 else 0.7
            reasons.append(f"Classified as Shadow AI ({confidence:.0%} confidence)")
        elif classification == "suspicious":
            risk_score = 0.6
            reasons.append("Suspicious traffic pattern")
            
        if is_anomalous:
            risk_score = max(risk_score, 0.5)
            # anomaly score is negative, lower is worse. -0.5 is worse than -0.2
            severity = "High" if anomaly_score < -0.4 else "Medium"
            reasons.append(f"{severity} Anomaly detected (score: {anomaly_score:.2f})")

        return {
            "is_anomalous": is_anomalous,
            "anomaly_score": round(anomaly_score, 3),
            "classification": classification,
            "confidence": round(confidence, 3),
            "risk_score": round(risk_score, 2),
            "reasons": reasons
        }

    def analyze_session(self, src_ip: str) -> Dict[str, Any]:
        """Get behavioral analysis for a specific IP."""
        return self.session_analyzer.analyze(src_ip)
