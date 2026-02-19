"""
Traffic Classifier — Supervised classification of network flows.

Categories: normal, suspicious, shadow_ai
Uses Random Forest for fast, interpretable predictions.
"""
import numpy as np
from loguru import logger

try:
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.preprocessing import LabelEncoder
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False


# Traffic categories
LABELS = ["normal", "suspicious", "shadow_ai"]


class TrafficClassifier:
    """
    Supervised traffic classifier.
    
    Requires labeled training data to distinguish between:
    - normal: Regular browsing, internal comms
    - suspicious: Unusual ports, high volume, unknown destinations
    - shadow_ai: Traffic matching AI service patterns
    """

    def __init__(self):
        self.model = None
        self.label_encoder = LabelEncoder()
        self.label_encoder.fit(LABELS)
        self.is_trained = False

        if SKLEARN_AVAILABLE:
            self.model = RandomForestClassifier(
                n_estimators=150,
                max_depth=10,
                min_samples_split=5,
                random_state=42,
                n_jobs=-1,
            )

    def train(self, X: np.ndarray, y: list):
        """
        Train the classifier.
        
        Args:
            X: Feature matrix (N x D)
            y: Labels list of strings ("normal", "suspicious", "shadow_ai")
        """
        if not SKLEARN_AVAILABLE:
            logger.warning("Cannot train: scikit-learn not available")
            return

        y_encoded = self.label_encoder.transform(y)
        logger.info(f"Training Traffic Classifier on {X.shape[0]} samples...")
        self.model.fit(X, y_encoded)
        self.is_trained = True

        # Log feature importances
        from services.intelligence.features.extractor import FeatureExtractor
        importances = self.model.feature_importances_
        for name, imp in sorted(
            zip(FeatureExtractor.FEATURE_NAMES, importances),
            key=lambda x: x[1], reverse=True
        ):
            logger.info(f"  Feature '{name}': {imp:.4f}")

    def predict(self, X: np.ndarray) -> list:
        """
        Classify traffic flows.
        
        Returns:
            List of category strings
        """
        if not self.is_trained or not SKLEARN_AVAILABLE:
            return self._fallback_predict(X)

        y_pred = self.model.predict(X)
        return self.label_encoder.inverse_transform(y_pred).tolist()

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        """
        Get classification probabilities.
        
        Returns:
            Array of shape (N, 3) with [normal, suspicious, shadow_ai] probabilities
        """
        if not self.is_trained or not SKLEARN_AVAILABLE:
            return np.array([[0.8, 0.1, 0.1]] * X.shape[0])

        return self.model.predict_proba(X)

    def _fallback_predict(self, X: np.ndarray) -> list:
        """Rule-based fallback when sklearn is unavailable."""
        if len(X.shape) == 1:
            X = X.reshape(1, -1)

        results = []
        for sample in X:
            is_external = sample[6] < 0.5    # not internal dst
            has_hostname = sample[9] > 0.5
            large_payload = sample[2] > 8.0   # log(bytes) > 8 ≈ 3KB+

            if is_external and has_hostname and large_payload:
                results.append("shadow_ai")
            elif is_external and not sample[7]:  # non-standard port
                results.append("suspicious")
            else:
                results.append("normal")

        return results

    def save(self, path: str):
        if SKLEARN_AVAILABLE and self.is_trained:
            import joblib
            joblib.dump({"model": self.model, "encoder": self.label_encoder}, path)
            logger.info(f"Classifier saved to {path}")

    def load(self, path: str):
        if SKLEARN_AVAILABLE:
            import joblib
            data = joblib.load(path)
            self.model = data["model"]
            self.label_encoder = data["encoder"]
            self.is_trained = True
            logger.info(f"Classifier loaded from {path}")
