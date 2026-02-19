# Shadow Hunter: The Comprehensive Technical Deep Dive

## Version 3.0 (Active Defense Edition)

**Target Audience**: Senior Engineers, Security Architects, and Hackathon Judges.
**Scope**: Line-by-line analysis of architecture, data flows, and Phase 6 Active Defense logic.

---

## 1. 🏗️ System Architecture & Data Flow

Shadow Hunter has evolved from a passive monitor to an **Active Defense System**. The architecture now includes a closed-loop feedback mechanism:

1.  **Event-Driven Backend**: Components communicate via an `EventBroker` (Publish/Subscribe).
2.  **Graph-Based State**: A `GraphStore` maintains the topology and supports **Centrality Analysis**.
3.  **Active Interrogation**: The system probes suspicious actors to verify threats.
4.  **Auto-Response**: The system autonomously manages a blocklist.

### Data Flow Pipeline (Updated)

1.  **Ingestion**: Traffic is captured (`sniffer.py`) or simulated (`traffic_generator.py`).
2.  **Normalization**: TLS Handshakes are parsed to extract **JA3 Fingerprints**.
3.  **Analysis**: The `AnalyzerEngine` receives the event.
    - **ML**: Classifies traffic (Shadow AI vs Normal).
    - **Identity**: Matches JA3 hashes against known tools.
    - **Graph**: Updates the network map.
4.  **Verification (Active Defense)**: High-risk events trigger the `ActiveProbe` to send HTTP/OPTIONS requests.
5.  **Decision**:
    - If `Critical`: **Auto-Block** via `ResponseManager`.
6.  **Visualization**: Live Graph & Alerts pushed to React Dashboard.

---

## 2. 🚀 The Bootstrapper: `run_local.py`

This script is the monolithic entry point that orchestrates the microservices.

### **Startup Sequence (v3.0)**

1.  **Infrastructure Initialization**:
    - `MemoryBroker`: Async Pub/Sub.
    - `SQLiteGraphStore`: **Persistent** graph database (replaced in-memory store).
2.  **Service Launch**:
    - **Analyzer**: `AnalyzerEngine(broker, store, active_defense=True)`.
    - **Listener/Simulator**: Starts packet capture.
3.  **API Server**: Launches `FastAPI` + `StaticFiles` (Dashboard).

---

## 3. 🧬 The DNA: Data Structures

### `pkg/models/events.py`

#### `class NetworkFlowEvent(BaseModel)`

Updated to include new fields for Phase 6:

| Field      | Type   | Description                                              |
| :--------- | :----- | :------------------------------------------------------- |
| `ja3_hash` | `str`  | **[New]** MD5 hash of TLS ClientHello packet.            |
| `metadata` | `dict` | Now includes `probe_result` (from Active Interrogation). |

---

## 4. 🧠 The Brain: `services/analyzer`

### `engine.py` (`AnalyzerEngine`)

The core logic has expanded significantly.

**New Logic Pipeline (`handle_traffic_event`)**:

1.  **ML Inference**: `IntelligenceEngine` predicts `Shadow AI` probability.
2.  **JA3 Matching**: `JA3Matcher` checks if client is `Cobalt Strike` or `Python Script`.
3.  **Active Probing**:
    - If `Risk > 0.8` AND `Target is External`:
    - Call `ActiveProbe.probe_host(target_ip)`.
    - If probe confirms AI API -> Risk set to `1.0`.
4.  **Graph Update**: Upserts node/edge to SQLite.
5.  **Auto-Response**:
    - If `Risk > 0.95` (CRITICAL):
    - Call `ResponseManager.block_ip(source_ip)`.

### `plugins/ja3_plugin.py` (**New Feature**)

- **Logic**: Compares `event.ja3_hash` against `pkg/data/ja3_intel.py`.
- **Detection**:
  - **Malware**: Exact match on known C2 triggers CRITICAL alert.
  - **Spoofing**: `User-Agent: Chrome` + `JA3: Python` triggers HIGH alert.

---

## 5. 🛡️ Active Defense: `services/active_defense`

### `interrogator.py` (**New Feature**)

The system now "talks back" to the network.

- **Class**: `ActiveProbe`
- **Methods**:
  - `probe_host(ip)`: Orchestrates the scan.
  - `_http_options(ip)`: Sends lightweight trace request.
  - `_ai_endpoint_check(ip)`: Sends `GET /v1/models` (OpenAI signature).
- **Safety**:
  - **Internal Guard**: Checks `is_internal(ip)` before sending a single packet.
  - **Rate Limiter**: max 10 probes/minute.

---

## 6. 🕸️ Graph Intelligence: `services/graph`

### `analytics.py` (**New Feature**)

Moves beyond simple connectivity to **Behavioral Analysis**.

- **Algorithm**: **Betweenness Centrality**.
- **Logic**:
  - Every 60 seconds, `run_analysis()` loads the graph from SQLite.
  - Calculates centrality scores for all internal nodes.
  - **Detection**: If a workstation (`192.168.x.x`) resembles a router (High Centrality), it flags **Lateral Movement**.

---

## 7. 🔒 Response: `services/response`

### `manager.py` (**New Feature**)

The automated SOAR component.

- **Class**: `ResponseManager`
- **Logic**:
  - Maintains an in-memory `Set` of blocked IPs.
  - **Whitelist**: Hardcoded protection for DNS (`8.8.8.8`) and Gateway (`.1`).
  - **Audit Trail**: Logs every block action with timestamp and reason.
  - **TTL**: Blocks expire after 1 hour to prevent permanent denial of service.

---

## 8. 📡 The Interface: `services/api`

### `routers/discovery.py`

Updated to serve the persistent graph.

- `GET /nodes`: Returns nodes with `risk_score` and `type`.
- `GET /edges`: Returns connections with `protocol` and `byte_count`.

### `routers/policy.py`

- `GET /blocked`: **[New]** Returns list of currently quarantined IPs.
- `POST /unblock`: **[New]** Manual override for analysts.

---

## 9. 🖼️ The Frontend: `services/dashboard`

### `GraphView.jsx`

- Now visualizes **Blocked Nodes** (Black color) and **High Centrality Nodes** (Larger size).
- Real-time updates via WebSocket now include `block_status`.

---

_This document reflects the state of the codebase after Phase 6 implementation._
