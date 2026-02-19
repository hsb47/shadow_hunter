"""
Shadow Autoencoder — Deep Learning anomaly detection via reconstruction error.

Architecture: Input(16) → 64 → 32 → 8 (bottleneck) → 32 → 64 → Output(16)

The autoencoder learns a compressed representation of "normal" traffic.
At inference, high reconstruction error = the traffic pattern differs
fundamentally from anything seen during training = anomalous.

This provides a fundamentally different signal from the Isolation Forest:
- Isolation Forest: Flags statistical outliers in feature space.
- Autoencoder: Flags patterns that can't be compressed/reconstructed.

Uses sklearn's MLPRegressor to avoid PyTorch/TensorFlow dependency.
"""
import numpy as np
from loguru import logger

try:
    from sklearn.neural_network import MLPRegressor
    from sklearn.preprocessing import StandardScaler
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False
    logger.warning("scikit-learn not installed. Autoencoder will use fallback.")


class ShadowAutoencoder:
    """
    Deep Learning autoencoder for unsupervised anomaly detection.

    Learns to reconstruct "normal" traffic patterns. Anomalous traffic
    produces high reconstruction error because the bottleneck can't
    encode patterns it hasn't seen before.

    Architecture:
        Input(16) → Dense(64, ReLU) → Dense(32, ReLU) → Dense(8, ReLU)
                  → Dense(32, ReLU) → Dense(64, ReLU) → Output(16)

    The bottleneck of 8 neurons forces the model to learn a compressed
    representation — only the most important features survive.
    """

    def __init__(self, contamination: float = 0.15):
        """
        Args:
            contamination: Expected proportion of anomalies.
                          Sets threshold at (1 - contamination) percentile.
        """
        self.contamination = contamination
        self.model = None
        self.scaler = None
        self.threshold = None
        self.training_errors = None
        self.is_trained = False
        self.n_features = 16  # Must match FeatureExtractor output

        if SKLEARN_AVAILABLE:
            # The architecture is encoded as hidden layers.
            # MLPRegressor trains target=input for autoencoder behavior.
            self.model = MLPRegressor(
                hidden_layer_sizes=(64, 32, 8, 32, 64),
                activation="relu",
                solver="adam",
                learning_rate_init=0.001,
                max_iter=500,
                early_stopping=True,
                validation_fraction=0.15,
                n_iter_no_change=20,
                random_state=42,
                verbose=False,
            )
            self.scaler = StandardScaler()

    def train(self, X: np.ndarray):
        """
        Train the autoencoder on normal traffic patterns.

        The model learns to reconstruct its own input (target = input).
        After training, computes reconstruction errors for all training
        samples and sets the anomaly threshold.

        Args:
            X: Feature matrix (N x D) of NORMAL traffic samples only
        """
        if not SKLEARN_AVAILABLE:
            logger.warning("Cannot train: scikit-learn not available")
            return

        if X.shape[0] < 10:
            logger.warning(f"Too few samples ({X.shape[0]}) to train autoencoder")
            return

        self.n_features = X.shape[1]
        logger.info(f"Training Autoencoder on {X.shape[0]} normal samples ({self.n_features} features)...")
        logger.info(f"  Architecture: {self.n_features} → 64 → 32 → 8 → 32 → 64 → {self.n_features}")

        # Scale features
        X_scaled = self.scaler.fit_transform(X)

        # Train: target = input (autoencoder self-reconstruction)
        self.model.fit(X_scaled, X_scaled)

        # Compute reconstruction errors for threshold calibration
        X_reconstructed = self.model.predict(X_scaled)
        self.training_errors = np.mean((X_scaled - X_reconstructed) ** 2, axis=1)

        # Set threshold at (1 - contamination) percentile
        self.threshold = np.percentile(
            self.training_errors,
            (1 - self.contamination) * 100
        )

        self.is_trained = True

        # Stats
        logger.info(f"  Mean training error: {np.mean(self.training_errors):.6f}")
        logger.info(f"  Threshold (p{(1-self.contamination)*100:.0f}): {self.threshold:.6f}")
        logger.info(f"  Max training error: {np.max(self.training_errors):.6f}")
        logger.info("Autoencoder trained successfully")

    def predict(self, X: np.ndarray) -> dict:
        """
        Analyze traffic for anomalies via reconstruction error.

        Args:
            X: Feature matrix (N x D), typically a single sample (1 x D)

        Returns:
            {
                "reconstruction_error": float,
                "is_anomalous": bool,
                "percentile": float (0-100),
                "per_feature_errors": dict (feature_name -> error),
                "threshold": float,
            }
        """
        if not self.is_trained or not SKLEARN_AVAILABLE:
            return self._fallback_predict(X)

        # Guard: feature count mismatch
        if X.shape[1] != self.n_features:
            logger.warning(
                f"Feature mismatch: autoencoder expects {self.n_features}, "
                f"got {X.shape[1]}. Using fallback."
            )
            return self._fallback_predict(X)

        X_scaled = self.scaler.transform(X)
        X_reconstructed = self.model.predict(X_scaled)

        # Per-feature squared errors
        feature_errors = (X_scaled - X_reconstructed) ** 2

        # Total reconstruction error (MSE)
        total_error = float(np.mean(feature_errors))

        # Percentile ranking against training distribution
        percentile = float(
            np.mean(self.training_errors <= total_error) * 100
        )

        # Per-feature error breakdown
        from services.intelligence.features.extractor import FeatureExtractor
        per_feature = {}
        for i, name in enumerate(FeatureExtractor.FEATURE_NAMES[:X.shape[1]]):
            per_feature[name] = float(feature_errors[0][i])

        return {
            "reconstruction_error": round(total_error, 6),
            "is_anomalous": total_error > self.threshold,
            "percentile": round(percentile, 1),
            "per_feature_errors": per_feature,
            "threshold": round(self.threshold, 6),
        }

    def _fallback_predict(self, X: np.ndarray) -> dict:
        """Heuristic fallback when model isn't available."""
        return {
            "reconstruction_error": 0.0,
            "is_anomalous": False,
            "percentile": 50.0,
            "per_feature_errors": {},
            "threshold": 0.0,
        }

    def save(self, path: str):
        """Save trained model, scaler, and threshold to disk."""
        if SKLEARN_AVAILABLE and self.is_trained:
            import joblib
            joblib.dump({
                "model": self.model,
                "scaler": self.scaler,
                "threshold": self.threshold,
                "training_errors": self.training_errors,
                "n_features": self.n_features,
            }, path)
            logger.info(f"Autoencoder saved to {path}")

    def load(self, path: str):
        """Load trained model from disk."""
        if SKLEARN_AVAILABLE:
            import joblib
            data = joblib.load(path)
            self.model = data["model"]
            self.scaler = data["scaler"]
            self.threshold = data["threshold"]
            self.training_errors = data["training_errors"]
            self.n_features = data.get("n_features", 16)
            self.is_trained = True
            logger.info(f"Autoencoder loaded from {path}")
