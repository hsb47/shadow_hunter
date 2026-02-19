# Shadow Hunter Project Documentation

## 1. Project Overview

**Shadow Hunter** is a real-time network monitoring solution designed to identify "Shadow AI" usage—unauthorized use of Generative AI tools within an enterprise network. It operates by analyzing network traffic (either real via packet capture or simulated) to detect connections to known AI services and anomalous traffic patterns.

The project follows a microservices-like architecture, with a shared `pkg` library and distinct `services` for different responsibilities.

### Architecture Highlights

- **Monolithic Entry Point**: `run_local.py` orchestrates the startup of all services in a single process for local deployment.
- **Event-Driven**: Components communicate via an `EventBroker` (currently in-memory, designed for Kafka).
- **Graph-Based**: Network state is maintained in a `GraphStore` (NetworkX for local, Neo4j ready).

---

## 2. Package Modules (`pkg`)

The `pkg` directory contains shared code, data structures, and interfaces used across all services.

### `pkg/core`

- **`interfaces.py`**: Defines the abstract base classes that enforce the contract for core infrastructure components.
  - `EventBroker`: Abstract base class for message brokers. Defines `publish` and `subscribe` methods.
  - `GraphStore`: Abstract base class for graph databases. Defines methods to add nodes (`add_node`) and edges (`add_edge`), and query the graph.

### `pkg/data`

- **`ai_domains.py`**: The "source of truth" for detecting Shadow AI.
  - `AI_DOMAIN_CATEGORIES`: A dictionary mapping over 120+ domains (e.g., `openai.com`, `midjourney.com`) to their category (`LLM`, `Image Gen`, `Code AI`, etc.).
  - `is_ai_domain(domain)`: Helper function to check if a domain is a known AI service, handling subdomains automatically.
  - `get_ai_category(domain)`: Returns the specific category of an AI domain.

### `pkg/models`

- **`events.py`**: Defines the data models for the application using Pydantic.
  - `Protocol`: Enum for network protocols (TCP, UDP, HTTP, HTTPS, DNS, etc.).
  - `NetworkFlowEvent`: The core data structure passed between services. Contains `source_ip`, `destination_ip`, `ports`, `protocol`, `bytes`, and `metadata` (like Sni, Host, or DNS query).

### `pkg/ingestion`

- **`producer.py`**: Handles sending events to the message broker.
  - `KafkaProducerWrapper`: A wrapper around `aiokafka` (or a mock) to serialize and publish `NetworkFlowEvent` objects to topics.

### `pkg/infra`

- **`local/`**: Implementations for local/demo environment.
  - `broker.py` ( inferred): Likely contains `MemoryBroker` implementation of `EventBroker`.
  - `store.py` (inferred): Likely contains `NetworkXStore` implementation of `GraphStore`.

---

## 3. Services

The `services` directory contains the functional logic of the application.

### `services/analyzer`

The "Brain" of the system. It consumes traffic events and determines if they represent security risks.

- **`engine.py` (`AnalyzerEngine`)**:
  - Subscribes to `sh.telemetry.traffic.v1`.
  - **Orchestration**:
    1.  Parses raw events into `NetworkFlowEvent`.
    2.  **Enrichment**: Determines if nodes are Internal, External, or Shadow AI based on IPs and domains.
    3.  **Graph Update**: Updates the `GraphStore` with new nodes and "TALKS_TO" edges.
    4.  **Detection**: Calls `AnomalyDetector` and `IntelligenceEngine`.
    5.  **Alerting**: If an anomaly/threat is found, constructs an alert object and broadcasts it via WebSocket (`transceiver`) and saves it.
- **`detector.py` (`AnomalyDetector`)**:
  - **Rule-Based Logic**: Contains hardcoded rules and heuristics.
  - `whitelist_ips` / `whitelist_ports`: Filters out noise like Multicast, UPnP, and Google Play Services to reduce false positives.
  - `detect(event)`: Checks for:
    - Known AI Domains (using `pkg.data.ai_domains`).
    - Outbound traffic on non-standard ports.
    - Potential DNS tunneling (large DNS payloads).

### `services/intelligence`

Advanced ML-based analysis to augment rule-based detection.

- **`engine.py` (`IntelligenceEngine`)**:
  - Loads trained models (`AnomalyModel`, `TrafficClassifier`) from `saved_models/`.
  - `analyze(event)`:
    - Updates session history for behavioral analysis.
    - Extracts features from the event.
    - Runs Anomaly Detection (Isolation Forest).
    - Runs Classification (Random Forest for specific threat types).
    - Calculates a `risk_score` (0.0 - 1.0) and assigns a confidence level.
- **`features/extractor.py`**: Transforms `NetworkFlowEvent` into numerical vectors for ML models.
- **`models/`**:
  - `anomaly.py`: Wraps the Isolation Forest model.
  - `classifier.py`: Wraps the Random Forest classifier.
  - `sequence.py` (`SessionAnalyzer`): Tracks state over time for a source IP (e.g., total bytes, connection limits) to detect behavioral anomalies.

### `services/listener`

Responsible for capturing real network traffic.

- **`sniffer.py` (`PacketProcessor`)**:
  - Uses **Scapy** to sniff packets on the network interface.
  - **DPI (Deep Packet Inspection)**:
    - Extracts HTTP Host headers.
    - Attempts to parse TLS SNI (Server Name Indication) to identify HTTPS domains.
    - Parses DNS queries.
  - Converts captured packets into `NetworkFlowEvent` objects.
  - Publishes events to the broker.

### `services/simulator`

Generates synthetic traffic for "Demo Mode" when real traffic capture isn't used.

- **`traffic_generator.py` (`TrafficGenerator`)**:
  - **Personas**: Simulates 5 distinct employees (Dev, Designer, Manager, DataSci, Intern) with specific "normal" browsing habits and "AI temptation" probabilities.
  - **Simulation Loop**:
    - Randomly generates "Normal" web traffic.
    - Randomly generates "Internal" server traffic (file shares, DBs).
    - Randomly generates **Shadow AI** traffic (HTTPS to `openai.com`, `huggingface.co`, etc.) based on the persona's role and temptation level.
  - Publishes these synthetic events to the broker, mimicking the `listener` service.

### `services/api`

Provides the backend for the frontend dashboard.

- **`main.py`**:
  - Initializes the FastAPI application (`Shadow Hunter Control Plane`).
  - Sets up CORS.
  - Exposes HTTP endpoints via routers (`/v1/discovery`, `/v1/policy`).
  - Exposes a **WebSocket endpoint** (`/ws`) for real-time frontend updates.
- **`transceiver.py`**:
  - `ConnectionManager`: Handles active WebSocket connections.
  - `broadcast(message)`: Pushes updates (alerts, graph changes) to all connected dashboard clients instantly.

### `services/dashboard`

The Frontend User Interface.

- **Technology**: React, Vite, Tailwind CSS.
- **Structure** (`src/`):
  - `App.jsx`: Main application layout.
  - **Visualizations**:
    - `GraphView.jsx`: Renders the force-directed network graph (likely using Cytoscape.js or similar).
    - `TrafficAnalytics.jsx`: Charts and graphs for traffic stats.
    - `Timeline.jsx`: Visualizes events over time.
  - **Management**:
    - `Policies.jsx`: Logic for managing blocking rules (implied).
    - `Alerts.jsx`: Displays the live feed of detected threats.
