"""
Anomaly Detection Model — Isolation Forest for unsupervised anomaly detection.

Detects unusual network flow patterns without needing labeled data.
Ideal for catching novel Shadow AI services not in any known list.
"""
import numpy as np
from loguru import logger

try:
    from sklearn.ensemble import IsolationForest
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False
    logger.warning("scikit-learn not installed. Anomaly model will use fallback heuristics.")


class AnomalyModel:
    """
    Unsupervised anomaly detection using Isolation Forest.
    
    Learns the "normal" traffic distribution and flags outliers.
    No labeled data required — perfect for zero-day Shadow AI detection.
    """

    def __init__(self, contamination: float = 0.05):
        """
        Args:
            contamination: Expected proportion of anomalies (0.05 = 5%)
        """
        self.contamination = contamination
        self.model = None
        self.is_trained = False

        if SKLEARN_AVAILABLE:
            self.model = IsolationForest(
                n_estimators=200,
                contamination=contamination,
                max_samples="auto",
                random_state=42,
                n_jobs=-1,
            )

    def train(self, X: np.ndarray):
        """
        Train the model on "normal" traffic patterns.
        
        Args:
            X: Feature matrix (N x D) of normal traffic samples
        """
        if not SKLEARN_AVAILABLE:
            logger.warning("Cannot train: scikit-learn not available")
            return

        logger.info(f"Training Anomaly Model on {X.shape[0]} samples...")
        self.model.fit(X)
        self.is_trained = True
        logger.info("Anomaly Model trained successfully")

    def predict(self, X: np.ndarray) -> np.ndarray:
        """
        Predict anomaly scores.
        
        Args:
            X: Feature matrix (N x D)
            
        Returns:
            Array of scores in [-1, 0]: lower = more anomalous
        """
        if not self.is_trained or not SKLEARN_AVAILABLE:
            return self._fallback_predict(X)

        # Guard: feature count mismatch (model trained on different feature set)
        expected = self.model.n_features_in_
        if X.shape[1] != expected:
            logger.warning(f"Feature mismatch: model expects {expected}, got {X.shape[1]}. Using heuristic fallback.")
            return self._fallback_predict(X)

        return self.model.decision_function(X)

    def is_anomalous(self, X: np.ndarray, threshold: float = -0.1) -> np.ndarray:
        """
        Binary anomaly classification.
        
        Returns:
            Boolean array: True = anomalous
        """
        scores = self.predict(X)
        return scores < threshold

    def _fallback_predict(self, X: np.ndarray) -> np.ndarray:
        """
        Heuristic fallback when sklearn is not available.
        Uses simple statistical outlier detection.
        """
        # Simple Z-score based anomaly detection
        if len(X.shape) == 1:
            X = X.reshape(1, -1)

        scores = np.zeros(X.shape[0])
        
        for i in range(X.shape[0]):
            sample = X[i]
            # Flag: large bytes + external destination + non-standard port
            byte_score = sample[2] + sample[3]  # log bytes
            is_external = 1.0 - sample[6]       # not internal dst
            unusual_port = 1.0 - sample[7]      # not well-known port
            
            risk = (byte_score * 0.3 + is_external * 0.4 + unusual_port * 0.3)
            scores[i] = -risk / 10.0  # Normalize to [-1, 0] range

        return scores

    def save(self, path: str):
        """Save trained model to disk."""
        if SKLEARN_AVAILABLE and self.is_trained:
            import joblib
            joblib.dump(self.model, path)
            logger.info(f"Anomaly Model saved to {path}")

    def load(self, path: str):
        """Load trained model from disk."""
        if SKLEARN_AVAILABLE:
            import joblib
            self.model = joblib.load(path)
            self.is_trained = True
            logger.info(f"Anomaly Model loaded from {path}")
