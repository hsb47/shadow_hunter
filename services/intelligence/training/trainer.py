"""
Model Trainer — End-to-end training pipeline.

Generates data, trains both models, evaluates, and saves to disk.

Usage:
    python -m services.intelligence.training.trainer
"""
import os
from loguru import logger

from services.intelligence.training.data_generator import TrainingDataGenerator
from services.intelligence.models.anomaly import AnomalyModel
from services.intelligence.models.classifier import TrafficClassifier


SAVE_DIR = os.path.join(os.path.dirname(__file__), "..", "saved_models")


def train_all(n_samples: int = 5000):
    """Run the full training pipeline."""
    os.makedirs(SAVE_DIR, exist_ok=True)
    
    # 1. Generate labeled data
    logger.info("=" * 60)
    logger.info("🧠 Shadow Hunter — Model Training Pipeline")
    logger.info("=" * 60)

    gen = TrainingDataGenerator()
    X, y = gen.generate(n_samples=n_samples)

    # 2. Train Anomaly Model (unsupervised — uses only "normal" samples)
    logger.info("\n--- Training Anomaly Detection Model ---")
    normal_mask = [label == "normal" for label in y]
    X_normal = X[normal_mask]
    
    anomaly_model = AnomalyModel(contamination=0.05)
    anomaly_model.train(X_normal)
    anomaly_model.save(os.path.join(SAVE_DIR, "anomaly_model.joblib"))

    # 3. Train Traffic Classifier (supervised — uses all labeled data)
    logger.info("\n--- Training Traffic Classifier ---")
    classifier = TrafficClassifier()
    classifier.train(X, y)
    classifier.save(os.path.join(SAVE_DIR, "classifier_model.joblib"))

    # 4. Quick evaluation
    logger.info("\n--- Quick Evaluation ---")
    evaluate(anomaly_model, classifier, X, y)

    logger.info("\n✅ All models trained and saved to: " + SAVE_DIR)


def evaluate(anomaly_model, classifier, X, y):
    """Quick evaluation of both models."""
    # Anomaly model
    scores = anomaly_model.predict(X)
    anomalous = anomaly_model.is_anomalous(X)
    
    # Check what percentage of shadow_ai it catches
    ai_mask = [label == "shadow_ai" for label in y]
    normal_mask = [label == "normal" for label in y]
    
    ai_caught = sum(1 for i, is_a in enumerate(anomalous) if is_a and ai_mask[i])
    ai_total = sum(ai_mask)
    normal_flagged = sum(1 for i, is_a in enumerate(anomalous) if is_a and normal_mask[i])
    normal_total = sum(normal_mask)
    
    logger.info(f"Anomaly Model:")
    logger.info(f"  Shadow AI detection rate: {ai_caught}/{ai_total} ({100*ai_caught/max(ai_total,1):.1f}%)")
    logger.info(f"  False positive rate: {normal_flagged}/{normal_total} ({100*normal_flagged/max(normal_total,1):.1f}%)")

    # Classifier
    predictions = classifier.predict(X)
    correct = sum(1 for p, t in zip(predictions, y) if p == t)
    logger.info(f"Classifier:")
    logger.info(f"  Accuracy: {correct}/{len(y)} ({100*correct/len(y):.1f}%)")

    # Per-class accuracy
    for label in ["normal", "suspicious", "shadow_ai"]:
        total = sum(1 for t in y if t == label)
        correct_class = sum(1 for p, t in zip(predictions, y) if p == t and t == label)
        logger.info(f"  {label}: {correct_class}/{total} ({100*correct_class/max(total,1):.1f}%)")


if __name__ == "__main__":
    train_all()
