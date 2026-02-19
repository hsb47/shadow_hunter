# AI / ML Detection Engine

## Overview

The **Shadow Hunter AI Engine** is responsible for analyzing network telemetry in real-time to identify:

1.  **Shadow AI Services:** Unauthorized usage of external GenAI APIs.
2.  **Anomalous Data Flows:** Data exfiltration or unusual communication patterns.
3.  **Policy Violations:** Usage of unapproved protocols or destinations.

## Architecture

The engine uses a tiered detection strategy, moving from heuristic signatures to behavioral modeling.

### Tier 1: Deep Packet Inspection (DPI) & Signatures (Current Implementation)

- **Input:** Layer 7 Metadata extracted by `sniffer.py` (HTTP Host, DNS Query, TLS SNI).
- **Logic:**
  - **Known AI Database:** Checks against `pkg/data/ai_domains.py` (e.g., `openai.com`, `huggingface.co`).
  - **Protocol Analysis:** Identifies HTTP/S and DNS traffic on non-standard ports.
- **Verdict:**
  - `KNOWN_AI`: Explicit match in the AI database.
  - `SHADOW_SERVICE`: Unclassified external service on standard HTTP/S ports.
  - `ANOMALY`: Traffic on unusual ports or protocols.

### Tier 2: Behavioral Anomaly Detection (Isolation Forest)

- **Input:** Flow features (Bytes Sent, Bytes Received, Duration, Frequency).
- **Algorithm:** **Isolation Forest** (Unsupervised Learning).
- **Logic:**
  - Builds a baseline of "normal" traffic volume and destinations.
  - Flags flows that deviate significantly (e.g., massive upload to an unknown IP).
- **Goal:** Detect data exfiltration or C2 (Command & Control) beacons.

### Tier 3: Causality Graph Analysis (Future)

- **Input:** The `Service Graph` (Nodes & Edges).
- **Logic:**
  - Detects "Inference Loops": Service A -> Service B -> OpenAI -> Service A.
  - Identifies "Shadow Chains": Internal Service -> Shadow Database -> External API.

## False Positive Reduction

- **Allowlisting:** Corporate subnets (`10.0.0.0/8`, etc.) are automatically trusted.
- **Confidence Scoring:** Alerts are tagged with `High`, `Medium`, or `Low` confidence based on the detection method (Signature match = High, Anomaly = Medium).

## Data Flow

1.  **Listener** captures packet -> extracts L7 metadata.
2.  **Broker** publishes `NetworkFlowEvent`.
3.  **Analyzer** consumes event -> runs `AnomalyDetector.detect()`.
4.  **GraphStore** updates connectivity graph.
5.  **Alerts** are published if detection triggers.
