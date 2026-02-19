# Shadow Hunter: The Comprehensive Technical Deep Dive

**Version**: 2.0
**Target Audience**: Senior Engineers, Security Architects, and Developers.
**Scope**: Line-by-line analysis of architecture, data flows, and component logic.

---

## 1. 🏗️ System Architecture & Data Flow

Shadow Hunter is a **real-time, event-driven network security monitoring platform**. It uses a hybrid architecture:

1.  **Event-Driven Backend**: Components communicate via an `EventBroker` (Publish/Subscribe pattern).
2.  **Graph-Based State**: A `GraphStore` maintains the topology of the network.
3.  **WebSocket-First Frontend**: The dashboard receives live updates, ensuring zero-latency visibility.

### Data Flow Pipeline

1.  **Ingestion**: Traffic is captured (`Listener`) or simulated (`Simulator`).
2.  **Normalization**: Raw packets -> `NetworkFlowEvent` objects.
3.  **Distribution**: Events are published to the `sh.telemetry.traffic.v1` topic.
4.  **Analysis**: The `Analyzer` subscribes to the topic.
    - **Enrichment**: Resolves internal/external/SRV records.
    - **Detection**: Runs Rule Engine + ML Models.
    - **Graph Update**: Updates Nodes/Edges in memory.
5.  **Notification**: Alerts are broadcast via WebSockets to the React Dashboard.

---

## 2. 🚀 The Bootstrapper: `run_local.py`

This script is the **Monolithic Entry Point** for development/local deployment. It avoids the complexity of orchestration tools (K8s/Docker Compose) by running all "microservices" as async tasks within a single Python process.

### **Startup Sequence**

1.  **CLI Argument Parsing**: Checks `sys.argv` for `--live`.
    - `LIVE_MODE = True`: Requires `Npcap` driver.
    - `LIVE_MODE = False`: Activates `DEMO` mode with synthetic traffic.
2.  **Infrastructure Initialization**:
    - Instance `MemoryBroker`: The in-memory replacement for Kafka.
    - Instance `NetworkXStore`: The in-memory replacement for Neo4j.
3.  **Dependency Injection**:
    - `set_graph_store(store)`: Makes the graph DB accessible to the API.
4.  **Service Launch**:
    - **Analyzer**: `AnalyzerEngine(broker, store).start()`
    - **Source**:
      - If Live: `ListenerService(broker).start()`
      - If Demo: `TrafficGenerator(broker).start()`
5.  **API Server**: Uses `uvicorn` to serve the `FastAPI` app on port `8000`.

---

## 3. 🧬 The DNA: Data Structures

### `pkg/models/events.py`

The "Lingua Franca" of the system. All components speak in `NetworkFlowEvent`s.

#### `class NetworkFlowEvent(BaseModel)`

| Field              | Type       | Description                                                      |
| :----------------- | :--------- | :--------------------------------------------------------------- |
| `timestamp`        | `datetime` | UTC time of packet capture.                                      |
| `source_ip`        | `str`      | Origin IP (e.g., "192.168.1.10").                                |
| `source_port`      | `int`      | Ephemeral port.                                                  |
| `destination_ip`   | `str`      | Target server IP.                                                |
| `destination_port` | `int`      | Target service port (443, 80).                                   |
| `protocol`         | `Enum`     | TCP, UDP, HTTP, HTTPS, DNS.                                      |
| `bytes_sent`       | `int`      | Payload size (critical for DLP detection).                       |
| `metadata`         | `dict`     | Flexible storage for DPI extraction: `host`, `sni`, `dns_query`. |

---

## 3.5 🏗️ Infrastructure: `pkg/infra/local`

To support the "local-first" philosophy without requiring heavy dependencies like Kafka or Neo4j, Shadow Hunter implements in-memory versions of its core interfaces.

### `broker.py` (`MemoryBroker`)

- **Implements**: `EventBroker` (from `pkg.core.interfaces`).
- **Mechanism**: Uses `asyncio.Queue` and `asyncio.create_task`.
- **Pub/Sub**:
  - `_queues`: A dict mapping topic strings to `asyncio.Queue` instances.
  - `_process_queues()`: A background loop that continuously pulls from queues and dispatches to registered callback functions.
- **Concurrency**: 100% async/await based, ensuring non-blocking operation within the single process.

### `store.py` (`NetworkXStore`)

- **Implements**: `GraphStore` (from `pkg.core.interfaces`).
- **Mechanism**: Wraps a `networkx.DiGraph`.
- **Operations**:
  - `add_node`: Upserts nodes, merging `labels` and properties.
  - `add_edge`: Creates directed edges. Note: It does not currently support multi-edges (multiple connections between same nodes), simplifying the model for MVP.
  - **Export**: Provides `get_all_nodes()` and `get_all_edges()` which serialize the graph directly to JSON for the `discovery` API.

---

## 4. 🧠 The Brain: `services/analyzer`

This service contains the core business logic for detection and topology building.

### `engine.py` (`AnalyzerEngine`)

- **Event Loop**: Subscribes to `sh.telemetry.traffic.v1`.
- **Logic Pipeline**:
  1.  **Node Classification**:
      - `Internal`: Matches `192.168/16`, `10/8`.
      - `Shadow AI`: Domain matches `pkg.data.ai_domains`.
      - `External`: Everything else.
  2.  **Graph Construction**:
      - Nodes are upserted with `last_seen`.
      - Edges ("TALKS_TO") store `byte_count` and `protocol`.
  3.  **Alert Generation**:
      - Alerts are **broadcast immediately** via `services.api.transceiver`.
      - Alerts are **stored** in `services.api.routers.policy._alerts_store` (circular buffer of 100).

### `detector.py` (`AnomalyDetector`)

The fast, heuristic-based rule engine.

- **Whitelisting**:
  - Ignores Multicast (`224.0.0.x`), SSDP (`239.255.255.250`), and Google Play Services ports (`5228`).
- **Detection Rules**:
  1.  **AI Domain Match**: Checks `metadata.host` or `metadata.sni` against the 120+ known domains in `pkg/data/ai_domains.py`.
  2.  **Abnormal Outbound Ports**: Internal IPs talking to External IPs on ports other than `80, 443, 8080, 22, 53`.
  3.  **DNS Tunneling**: DNS packets > 500 bytes.

---

## 5. 📡 The Interface: `services/api`

### `routers/policy.py`

More than just a router—this file houses significant business logic.

- **In-Memory Stores**:
  - `_alerts_store`: Holds the last 100 alerts.
  - `_policy_rules`: Mutable list of blocking/monitoring rules.
- **Advanced Logic**:
  - **`get_compliance()`**: Calculates SOC2/GDPR/HIPAA scores based on:
    - Number of "Shadow AI" alerts (Risk).
    - Number of "High Severity" alerts (Risk).
    - Number of Blocking Rules (Mitigation).
  - **`get_briefing()`**: Uses string templates to generate a natural-language "Executive Summary" of the current threat landscape.
  - **`get_killchain()`**: Maps alerts to MITRE ATT&CK stages (Reconnaissance -> Exfiltration) using keyword matching on alert descriptions.

### `transceiver.py` (`ConnectionManager`)

- Manages WebSocket connections (`ws://localhost:8000/ws`).
- **`broadcast(message)`**: Iterates over all active sockets. Handles disconnect cleanup automatically.

---

## 6. 🖼️ The Frontend: `services/dashboard`

A complex React Application managed by Vite.

### Core Components

#### `App.jsx`

- **State Management**:
  - `activeTab`: Controls the view (Dashboard, Network, Alerts, etc.).
  - `isLiveMode`: Displayed in the header.
  - `stats`: Aggregate counts (Nodes, Edges, Alerts).
- **WebSocket Integration**:
  - Connects to `/ws` on mount.
  - On message `type: "alert"` -> Triggers immediate `fetchStats()` refresh.
  - **Browser Notifications**: Uses the Notification API to show system-level toasts for HIGH severity alerts.

#### `GraphView.jsx`

- **Library**: `Cytoscape.js`.
- **Styling**:
  - **Internal**: Blue Squares (`shape: round-rectangle`).
  - **External**: Green Circles (`shape: ellipse`).
  - **Shadow AI**: Red Hexagons (`shape: hexagon`, with `shadow-blur`).
- **Interaction**: Click node -> Slide-out panel with connection details and specific alert history.

#### `ComplianceBoard.jsx`

- **Visualization**: SVG-based Gauge Chart.
- **Logic**: Displays pass/warn/fail status for individual controls (e.g., "PII Protection", "Access Monitoring") derived from the `GET /policy/compliance` endpoint.

#### `ExecutiveBriefing.jsx`

- **Purpose**: Renders the JSON briefing from the backend into a clean, readable report.
- **Dynamic UX**: Uses color coding (Red/Orange/Green) based on the computed `threat_level`.

### Data Fetching (`api.js`)

- **Axios Wrapper**: Configured with `baseURL: http://localhost:8000/v1`.
- **Endpoints**:
  - `fetchGraphData` -> `/discovery/nodes` & `/discovery/edges`.
  - `fetchAlerts` -> `/policy/alerts` (The live feed).
  - `fetchRiskScores` -> `/discovery/risk-scores` (Calculated top offenders).

### Additional Visualization Modules

The dashboard is composed of several specialized view components, each consuming a specific API slice:

| Component              | API Endpoint               | Description                                                 |
| :--------------------- | :------------------------- | :---------------------------------------------------------- |
| `TrafficAnalytics.jsx` | `/discovery/traffic-stats` | Visualization of bandwidth and protocol usage over time.    |
| `Timeline.jsx`         | `/policy/timeline`         | Chronological feed of security events and alerts.           |
| `UserProfiles.jsx`     | `/policy/profiles`         | Identity-centric view aggregating risks by user/IP.         |
| `SessionTracking.jsx`  | `/policy/sessions`         | Logical grouping of flows into user sessions.               |
| `DlpMonitor.jsx`       | `/policy/dlp`              | Specialized view for high-volume data exfiltration events.  |
| `KillChain.jsx`        | `/policy/killchain`        | Maps alerts to the MITRE ATT&CK lifecycle (Recon -> Exfil). |

### Reporting Engine

- **`generatePdfReport.js`**: A client-side PDF generator using `jspdf`.
  - **No Server Load**: Generates reports entirely in the browser.
  - **Visuals**: Draws the "Shadow Hunter" logo, summary cards, severity bar charts, and data tables (Top Sources/Targets) using raw HTML5 Canvas-like drawing commands (`rect`, `text`, `roundedRect`).

---

## 7. 🧪 The Simulator: `services/simulator`

Used for "Demo Mode". It does **not** rely on randomness alone; it uses **Personas**.

### `traffic_generator.py`

- **Personas**:
  - **Dev_Ravi**: Uses GitHub, StackOverflow. High risk for Copilot/ChatGPT.
  - **Designer_Priya**: Uses Figma, Dribbble. High risk for Midjourney.
  - **Intern_Kiran**: Uses Everything. Highest risk.
- **Behavior Loop**:
  - Sleeps 2-5s between actions.
  - **Traffic Types**:
    - **Web**: Normal HTTPS traffic to safe sites.
    - **Internal**: Traffic to file servers/DBs.
    - **Shadow AI**: Triggered by `ai_temptation` probability. Generates large payload HTTPS traffic to `ai_domains`.

---

## 8. 🛡️ The Listener: `services/listener`

### `sniffer.py` (`PacketProcessor`)

- **Library**: `Scapy`.
- **DPI Logic**:
  - **HTTP**: Decodes TCP payload, searches for `Host: <domain>`.
  - **HTTPS**: Inspects TLS Client Hello (0x16) for SNI Extension. _Note: The current implementation uses a heuristic/placeholder for SNI parsing robustness._
  - **DNS**: Decodes UDP payload, extracts query name from `DNSQR`.

---

## 9. 🤖 Intelligence: `services/intelligence`

### `engine.py`

- **Hybrid Approach**:
  - Combines **Isolation Forest** (Anomaly Detection) and **Random Forest** (Traffic Classification).
- **Risk Scoring**:
  - Calculates a 0.0-1.0 score based on ML confidence + Rule severity + Historical behavior.
- **Session Tracking**:
  - `sequence.py`: Maintains a running window of user activity to detect behavioral shifts (e.g., "Intern Kiran suddenly uploading 5GB of data").
