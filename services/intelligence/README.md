# Shadow Hunter — Intelligence Module

Real traffic analysis engine powered by ML models.

## Structure

```
services/intelligence/
├── __init__.py
├── engine.py              # Main inference engine (takes flow → returns verdict)
├── features/
│   ├── __init__.py
│   └── extractor.py       # Extract features from NetworkFlowEvents
├── models/
│   ├── __init__.py
│   ├── anomaly.py          # Isolation Forest anomaly detection
│   ├── classifier.py       # Traffic classifier (normal/suspicious/shadow)
│   └── sequence.py         # Session sequence analysis (behavioral patterns)
├── training/
│   ├── __init__.py
│   ├── trainer.py          # Model training pipeline
│   ├── data_generator.py   # Generate labeled training data
│   └── evaluate.py         # Model evaluation & metrics
└── saved_models/           # Serialized trained models (.joblib)
    └── .gitkeep
```

## Usage

```python
from services.intelligence.engine import IntelligenceEngine

engine = IntelligenceEngine()
engine.load_models()

verdict = engine.analyze(flow_event)
# verdict = { "risk_score": 0.87, "classification": "shadow_ai", "confidence": 0.92 }
```
