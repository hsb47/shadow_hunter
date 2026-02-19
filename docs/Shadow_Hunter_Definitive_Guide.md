# 🦅 Shadow Hunter: The Definitive Guide

> **Version:** Final (Phase 6 Complete)
> **Author:** Antigravity AI

This document consolidates all project knowledge into a single source of truth. It covers architecture, usage, algorithms, and code structure "grain-to-grain".

---

## 📚 Table of Contents

1.  [Philosophy & Goals](#1-philosophy--goals)
2.  [System Architecture](#2-system-architecture)
3.  [Feature Deep Dive (Active Defense)](#3-feature-deep-dive-active-defense)
4.  [The AI Engine (Algorithms)](#4-the-ai-engine-algorithms)
5.  [Codebase Reference (Grain-to-Grain)](#5-codebase-reference-grain-to-grain)
6.  [Database Schema](#6-database-schema)
7.  [API Reference](#7-api-reference)
8.  [Demo Walkthrough Script](#8-demo-walkthrough-script)
9.  [Setup & Troubleshooting](#9-setup--troubleshooting)

---

## 1. Philosophy & Goals

**Shadow Hunter** is an **Active Defense AI** designed to secure networks against advanced threats (Shadow AI, Lateral Movement) that evade signature-based firewalls.

- **Passive vs. Active:** Traditional IDS watches. Shadow Hunter _hunts_ (probes suspicious IPs) and _acts_ (auto-blocking).
- **Identity vs. Metadata:** We don't trust user-agents. We use **JA3 Fingerprinting** to cryptographically verify client identity.
- **Graph vs. Logs:** Analyzing single packets is old school. We analyze the **Network Graph** to find bridges and pivots.

---

## 2. System Architecture

The system follows a microservices-inspired pipeline architecture, running as a monolithic process for ease of deployment (`run_local.py`).

### Data Flow

1.  **Listener (`sniffer.py`)**: Captures raw packets. Extracts JA3.
2.  **Broker (`broker.py`)**: Async Pub/Sub bus. Decouples capture from analysis.
3.  **Analyzer (`engine.py`)**: The Brain.
    - **Enrichment**: Adds GeoIP/ASN.
    - **Detection**: Runs ML + Rules + JA3.
    - **Graph**: Updates `shadow_hunter.db`.
4.  **Active Defense (`interrogator.py`)**: Probes high-risk external targets.
5.  **Response (`manager.py`)**: Blocks CRITICAL threats.
6.  **Dashboard**: Visualizes the live graph via WebSockets.

---

## 3. Feature Deep Dive (Active Defense)

### Feature 1: JA3 Client Fingerprinting

- **Risk:** Malware impersonating "Chrome".
- **Solution:** Hashes the TLS ClientHello (Ciphers+Extensions).
- **Logic:** `pkg/data/ja3_intel.py` contains 18 known signatures (Cobalt Strike, Python, Trickbot).
- **Alert:** `Spoofing Detected` if User-Agent != JA3 Signature.

### Feature 2: Active Interrogation

- **Risk:** Unknown "Shadow AI" APIs.
- **Solution:** `ActiveProbe` sends HTTP `OPTIONS /` and `GET /v1/models`.
- **Safety:** Never probes Internal IPs. Rate-limited (10/min).

### Feature 3: Graph Centrality

- **Risk:** Lateral Movement (Compromised laptop scanning servers).
- **Solution:** `GraphAnalyzer` runs **Betweenness Centrality** every 60s.
- **Math:** $C_B(v) = \sum \sigma_{st}(v) / \sigma_{st}$.
- **Alert:** "High Centrality" on an endpoint node.

### Feature 4: Auto-Response

- **Risk:** Fast-moving ransomware.
- **Solution:** `ResponseManager` keeps an in-memory blocklist.
- **Logic:** CRITICAL Alert -> Block IP for 1 hour. Whitelists DNS/Gateways.

---

## 4. The AI Engine (Algorithms)

### A. Deep Learning Autoencoder

- **Role:** Zero-Day Anomaly Detection.
- **Theory:** Trained on "Normal" traffic. Malicious traffic has high **Reconstruction Error**.
- **Input:** Packet size sequences, Inter-arrival times.

### B. Random Forest Classifier

- **Role:** Traffic Classification.
- **Classes:** `Normal`, `Suspicious`, `Shadow_AI`.
- **Features:** SNI, Cert Issuer, Entropy.

### C. Isolation Forest

- **Role:** Statistical Outlier Detection.
- **Theory:** Anomalies are "few and different" (easier to isolate).

---

## 5. Codebase Reference (Grain-to-Grain)

This section details the implementation of every key component, mapping files to their specific responsibilities and algorithms.

### 📂 Root

#### `run_local.py`

- **Monolith Entry Point**: Orchestrates the startup of all services.
- **Modes**:
  - `DEMO` (Default): Uses `TrafficGenerator` to simulate employees.
  - `LIVE` (`--live`): Requires root/admin for Scapy packet capture.
- **Logic**: Initializes `MemoryBroker`, `SQLiteGraphStore`, and starts the `uvicorn` server for the API.

---

### 📂 `pkg/` — Shared Core & Data

#### `pkg/core/interfaces.py`

- **`EventBroker` (ABC)**: Defines the contract for the message bus. Methods: `publish()`, `subscribe()`.
- **`GraphStore` (ABC)**: Defines the contract for the graph database. Methods: `add_node()`, `add_edge()`, `get_all_nodes()`.

#### `pkg/data/`

- **`ja3_intel.py`**:
  - **`JA3Matcher`**: Pre-indexes `JA3_DATABASE` (list of dictionaries) for O(1) lookups.
  - **`detect_spoofing(ja3_hash, user_agent)`**: Logic to catch tools impersonating browsers. Checks if `User-Agent` claims "Chrome" but JA3 matches "Python requests".
  - **Database**: Contains 18+ fingerprints including _Cobalt Strike Beacon_, _Metasploit_, _Mirai_, and standard browsers.
- **`cidr_threat_intel.py`**:
  - **`CIDRMatcher`**: Compiles `AI_CIDR_DATABASE` into `ipaddress.ip_network` objects.
  - **Logic**: Matches destination IPs against known ranges for OpenAI, Anthropic, Google Vertex, etc. Returns `ThreatIntelMatch` with risk levels.
- **`ai_domains.py`**:
  - **`is_ai_domain(domain)`**: Validates domains against a set of 120+ GenAI providers (_OpenAI, Midjourney, HuggingFace_). Handles subdomain matching.

#### `pkg/infra/local/`

- **`broker.py` (`MemoryBroker`)**:
  - Implements `EventBroker` using `asyncio.Queue`.
  - **`_process_queues()`**: Background task that dispatches messages to subscribers.
  - **Usage**: Decouples the blocking Scapy sniffer from the AsyncIO analyzer engine.

#### `pkg/models/events.py`

- **`NetworkFlowEvent`**: Pydantic model for internal telemetry.
  - Fields: `source_ip`, `destination_ip`, `protocol` (Enum: TCP/UDP/HTTP/DNS), `metadata` (Dict).
  - **Normalization**: All raw packets convert to this structure before analysis.

---

### 📂 `services/listener` — Traffic Capture

#### `sniffer.py`

- **`PacketProcessor`**:
  - **`process_packet_callback(packet)`**: Runs in Scapy's thread. Pushes raw packets to an `asyncio.Queue` (buffer size 1000) to prevent packet loss.
  - **`_process_single(packet)`**: The "DPI" (Deep Packet Inspection) engine.
    - **HTTP**: Extracts `Host` header.
    - **TLS**: Parses Client Hello to extract **SNI** and calculate **JA3** (MD5 of handshake fields).
    - **DNS**: Extracts query name (`qname`).
  - **Optimization**: Ignores non-IP traffic and filters internal broadcast noise.

---

### 📂 `services/analyzer` — The Brain

#### `engine.py` (`AnalyzerEngine`)

- **Orchestrator**: The central loop of the application.
- **`handle_traffic_event(event)`**:
  1.  **Enrichment**: Resolves `src`/`dst` types (Internal vs External vs Shadow AI).
  2.  **Graph Update**: Async calls to `graph.add_node()` and `graph.add_edge()` (concurrent `asyncio.gather`).
  3.  **Detection Pipeline**:
      - **Rule-based**: Calls `AnomalyDetector`.
      - **ML-based**: Calls `IntelligenceEngine` (if models loaded).
      - **Intelligence**: query `JA3Matcher` and `CIDRMatcher`.
  4.  **Alerting**: Generates `alert` objects with enriched context (JA3 details, AI risk scores).
  5.  **Active Defense**: Triggers `ActiveProbe` for CRITICAL alerts.
  6.  **Auto-Response**: Calls `ResponseManager` to block IPs if severity is CRITICAL.

#### `detector.py` (`AnomalyDetector`)

- **Rule Engine**: Simple boolean logic for immediate threats.
- **`detect(event)`**: Checks against loaded plugins (e.g., "Block Port 445", "Flag non-standard ports").

---

### 📂 `services/active_defense` — Verifier

#### `interrogator.py` (`ActiveProbe`)

- **Safety First**: Checks `_is_internal_ip()` and `_is_rate_limited()` before any network activity.
- **`interrogate(target)`**: Sequence of probes:
  1.  **`probe_http_options()`**: Sends `OPTIONS /`. Checks `Server`, `X-Request-ID`, `Access-Control-Allow-Origin` headers.
  2.  **`probe_ai_endpoint()`**: Sends `GET /v1/models` (OpenAI style) or `/api/tags` (Ollama style).
  3.  **Verdict**: Returns `confirmed_ai: True` if signature headers or JSON responses match known AI schemas.

---

### 📂 `services/graph` — Lateral Movement

#### `analytics.py` (`GraphAnalyzer`)

- **`detect_lateral_movement()`**:
  - Runs periodically (every 60s).
  - Builds a **NetworkX** DiGraph from the persistent store.
  - Calculates **Betweenness Centrality** ($C_B(v)$).
  - **Logic**: Identifies "Bridge Nodes" — internal IPs with high centrality that connect disparate subnets.
  - **Filtering**: Ignores known infrastructure (Gateways, DNS) via `INFRASTRUCTURE_PATTERNS`.

---

### 📂 `services/api` — Integration Layer

#### `main.py`

- **FastAPI Core**: Serves the REST API and mounts the dashboard.
- **Routers**:
  - `policy.py`: Handles alerts, blocking, and compliance logic.
  - `discovery.py`: Serves graph data for the 3D visualization.
- **Middleware**: Configures CORS to allow the Vite-based dashboard to communicate with the backend.

---

### 📂 `services/intelligence` — ML Engine

#### `engine.py` (`IntelligenceEngine`)

- **Combined Inference**: Orchestrates three distinct models for maximum coverage.
- **`analyze(event)`**:
  1.  **Feature Extraction**: Converts packet size/timing sequences into numerical vectors.
  2.  **`AnomalyModel` (Isolation Forest)**: Unsupervised detection of statistical outliers (Score < -0.2).
  3.  **`TrafficClassifier` (Random Forest)**: Supervised classification into `Normal`, `Suspicious`, or `Shadow_AI`.
  4.  **`ShadowAutoencoder`**: Deep Learning reconstruction error for zero-day anomalies.
  5.  **Risk Scoring**: Fuses confidence scores from all models. E.g., if IF and AE both flag it -> Risk 0.85+.
- **`session_analyzer`**: Tracks behavior over time (e.g., total bytes, velocity) to catch slow-drip exfiltration.

---

### 📂 `services/response` — Auto-Remediation

#### `manager.py` (`ResponseManager`)

- **`block_ip(ip, severity)`**:
  - **Whitelist Check**: Protects DNS (8.8.8.8) and Gateways.
  - **State**: Adds IP to in-memory `_blocked` dict with a TTL (default 1 hour).
  - **Audit**: Logs every action to `_audit_log`.
- **`is_blocked(ip)`**: Checked by the simulated firewall to drop traffic.

---

## 6. Database Schema

**File:** `shadow_hunter.db` (SQLite)

### Table: `nodes`

| Column       | Type      | Description                                                         |
| :----------- | :-------- | :------------------------------------------------------------------ |
| `id`         | TEXT (PK) | IP Address (e.g., `192.168.1.5`) or Domain (`google.com`).          |
| `labels`     | TEXT      | JSON List using `["Node"]`.                                         |
| `properties` | TEXT      | JSON Object. Contains `type` (`internal`/`external`), `risk_score`. |

### Table: `edges`

| Column       | Type      | Description                                                                            |
| :----------- | :-------- | :------------------------------------------------------------------------------------- |
| `source`     | TEXT (FK) | Origin IP.                                                                             |
| `target`     | TEXT (FK) | Destination IP/Domain.                                                                 |
| `relation`   | TEXT      | Usually `TALKS_TO`.                                                                    |
| `properties` | TEXT      | JSON Object. Contains `protocol` (`TCP`/`UDP`), `dst_port`, `byte_count`, `last_seen`. |

---

## 7. API Reference

**Base URL:** `http://localhost:8000/api/v1`

### 🛡️ Policy & Alerting (`/policy`)

| Endpoint      | Method     | Description                                                   |
| :------------ | :--------- | :------------------------------------------------------------ |
| `/alerts`     | `GET`      | Real-time threat feed of active security incidents.           |
| `/blocked`    | `GET`      | List of currently quarantined IPs (Active Defense).           |
| `/rules`      | `GET/POST` | CRUD for policy rules (e.g., "Block ChatGPT for Finance").    |
| `/compliance` | `GET`      | SOC2/GDPR/HIPAA compliance scoring based on traffic.          |
| `/briefing`   | `GET`      | AI-generated executive threat summary (Natural Language).     |
| `/dlp`        | `GET`      | Data Loss Prevention incidents (PII/API Key leaks).           |
| `/timeline`   | `GET`      | Alert distribution bucketed by minute for time-series charts. |
| `/sessions`   | `GET`      | User activity sessions grouped by 5-minute windows.           |
| `/profiles`   | `GET`      | Behavioral profiles (typical hours, top destinations) per IP. |
| `/report`     | `GET`      | Summary statistics of Shadow AI usage and top offenders.      |

### 🔍 Discovery & Graph (`/discovery`)

| Endpoint         | Method | Description                                      |
| :--------------- | :----- | :----------------------------------------------- |
| `/nodes`         | `GET`  | All graph nodes for D3.js/Cosmos visualization.  |
| `/edges`         | `GET`  | All graph connections (dependencies).            |
| `/risk-scores`   | `GET`  | Calculated risk scores (0-100) per internal IP.  |
| `/traffic-stats` | `GET`  | Protocol breakdown and device type distribution. |

---

## 8. Demo Walkthrough Script

**Prerequisite:** Run `python run_local.py` (Demo Mode). This starts a simulation of **5 virtual employees** generating realistic traffic patterns.

**Step 1: The Baseline (0:00)**

- **Action:** Open Dashboard (`http://localhost:5173`).
- **Visual:** You see the 3D Force Graph building live. Blue nodes are internal devices, green are external websites.
- **Narrative:** "This is a living map of our network. The system is currently observing standard business traffic—email, browsing, cloud storage."

**Step 2: The anomaly (0:45)**

- **Event:** A "Shadow AI Usage" alert triggers. A node connects to an unknown external IP.
- **Visual:** The connection turns **YELLOW**.
- **Narrative:** "Our ML engine detected a deviation. Employee 'Bob' is sending large payloads to an unclassified endpoint. Most firewalls would miss this because it looks like generic HTTPS."

**Step 3: Verification (1:15)**

- **Action:** Check the "Active Monitoring" log in the dashboard.
- **Log:** `[ACTIVE DEFENSE] Probing host 142.250.x.x...` -> `[CONFIRMED] Target is Google Gemini API`.
- **Narrative:** "Shadow Hunter didn't just guess. It actively probed the destination, confirming it's an AI service despite the encrypted traffic."

**Step 4: Auto-Remediation (2:00)**

- **Event:** The risk score hits **Critical (0.95)** due to data exfiltration pattern.
- **Visual:** The node turns **RED** and connections are severed.
- **Narrative:** "The system automatically updated the firewall rules. The device is quarantined, and the session is terminated before sensitive data is lost."

---

## 9. Setup & Troubleshooting

### Prerequisites

- Python 3.10+
- Node.js 18+ (for Dashboard)
- Npcap (for Live Capture on Windows)

### Commands

```bash
# Start Backend
python run_local.py         # Demo Mode
python run_local.py --live  # Live Mode (Needs Root/Admin)

# Start Frontend
cd services/dashboard
npm run dev
```

### Common Issues

- **"Address in use"**: Kill python process using port 8000.
- **"Database locked"**: Close `inspect_db.py`.
- **"No alerts"**: Wait 1-2 mins for simulation to roll various scenarios.

---

_End of Definitive Guide_
