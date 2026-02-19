# 📜 Shadow Hunter: The Master Reference

> **Version:** 1.0.0 (Phase 6 Complete)
> **Goal:** Active Defense AI for Modern Networks

This document serves as the definitive technical reference for the Shadow Hunter codebase, covering every file, function, and configuration option "grain-to-grain".

---

## 📂 1. Project Structure (The Anatomy)

```plaintext
shadow_hunter/
├── run_local.py                # ENTRY POINT: Bootstraps the entire system.
├── shadow_hunter.db            # DATABASE: Stores the Network Graph (Nodes + Edges).
├── inspect_db.py               # UTILITY: CLI tool to view DB contents.
│
├── pkg/                        # SHARED PACKAGES
│   ├── core/                   # INTERFACES (Clean Architecture)
│   │   ├── interfaces.py       # Abstract Base Classes (EventBroker, GraphStore).
│   ├── data/                   # KNOWLEDGE BASES
│   │   ├── ai_domains.py       # List of 50+ AI API domains (OpenAI, HuggingFace).
│   │   ├── cidr_threat_intel.py# Malicious IP ranges & Cloud Providers.
│   │   ├── ja3_intel.py        # 18 JA3 Fingerprints (Cobalt Strike, Python, Chrome).
│   ├── infra/                  # INFRASTRUCTURE ADAPTERS
│   │   ├── local/
│   │       ├── broker.py       # InMemory Message Bus (Pub/Sub).
│   │       ├── store.py        # NetworkX Graph Store (In-Memory).
│   │       ├── sqlite_store.py # Persistent Graph Store (Disk-based).
│   ├── models/                 # DATA MODELS (Pydantic)
│       ├── events.py           # NetworkFlowEvent, Alert schemas.
│
├── services/                   # MICROSERVICES
│   ├── active_defense/         # FEATURE 2: ACTIVE INTERROGATION
│   │   ├── interrogator.py     # Logic to probe suspicious IPs (HTTP OPTIONS/GET).
│   ├── analyzer/               # THE BRAIN
│   │   ├── engine.py           # Main Loop: Orchestrates ML, Rules, Graph, Response.
│   │   ├── detector.py         # Rule Engine: Loads plugins.
│   │   ├── plugins/            # PLUGINS
│   │       ├── ja3_plugin.py   # FEATURE 1: Detects tool spoofing.
│   │       ├── cidr_plugin.py  # Detects bad IPs.
│   ├── api/                    # REST API (FastAPI)
│   │   ├── main.py             # Server setup.
│   │   ├── routers/
│   │       ├── policy.py       # Alert Management Endpoints.
│   │       ├── discovery.py    # Graph Data Endpoints.
│   ├── dashboard/              # FRONTEND (React + Vite)
│   │   ├── src/                # UI Source Code.
│   ├── graph/                  # FEATURE 3: GRAPH ANALYTICS
│   │   ├── analytics.py        # Centrality Algorithm (Brandes).
│   ├── intelligence/           # MACHINE LEARNING ENGINE
│   │   ├── engine.py           # ML Pipeline (Autoencoder + Classifier).
│   │   ├── models/             # Saved .joblib models.
│   ├── listener/               # THE EARS
│   │   ├── sniffer.py          # Scapy Sniffer (Raw Packet Capture).
│   ├── response/               # FEATURE 4: AUTO-RESPONSE
│       ├── manager.py          # Blocklist Manager (Simulated Firewall).
```

---

## 🧬 2. Module Deep Dive (Logic & Algorithms)

### A. The Listener (`services/listener/sniffer.py`)

- **Purpose:** Captures raw packets off the wire.
- **Key Logic:**
  - `_process_packet()`: Filters `ARP/DHCP`. Extracts `IP`, `TCP`, `UDP`.
  - **JA3 Extraction:** Parses `TLS ClientHello` → extracts `CipherSuites`, `Extensions` → MD5 Hash.
  - **Normalization:** Output is a uniform `NetworkFlowEvent`.

### B. The Intelligence Engine (`services/intelligence/engine.py`)

- **Purpose:** ML-based classification.
- **Algorithms:**
  1.  **Isolation Forest:** Unsupervised Anomaly Detection. (Score < -0.2 = Anomaly).
  2.  **Random Forest:** Classifier (`Normal` vs `Shadow_AI`).
  3.  **Autoencoder:** Deep Learning Reconstruction Error (Zero-Day Detection).
- **Input Features:** Packet Size, Inter-arrival Time, Entropy, Port.

### C. The Active Interrogator (`services/active_defense/interrogator.py`)

- **Purpose:** Verify suspicious destinations through probing.
- **Logic:**
  1.  **Safety Check:** `if ip_type == "internal": return` (Never probe internal).
  2.  **Rate Limit:** Max 1 probe per 10s per target.
  3.  **Probe 1:** HTTP `OPTIONS /`. Checks `Server` header.
  4.  **Probe 2:** HTTP `GET /v1/models`. Checks for AI API JSON response.

### D. Graph Analytics (`services/graph/analytics.py`)

- **Purpose:** Detect Lateral Movement.
- **Logic:**
  1.  **Build Graph:** Loads `nodes` and `edges` from SQLite into `NetworkX`.
  2.  **Calculate Centrality:** `nx.betweenness_centrality()`.
  3.  **Threshold:** If `centrality > 0.1` AND `node_type == "internal"`, flag as **Bridge**.

### E. Response Manager (`services/response/manager.py`)

- **Purpose:** Automated Blocking.
- **Logic:**
  1.  **Trigger:** Alert Severity == `CRITICAL`.
  2.  **Safeguard:** Whitelist `Gateway`, `DNS`.
  3.  **Action:** Add to `self._blocked` list.
  4.  **TTL:** Unit expires after 3600s (1 hour).

---

## 💾 3. Data Schema (The Database)

**File:** `shadow_hunter.db` (SQLite)

### Table: `nodes`

| Column       | Type      | Description                                                         |
| :----------- | :-------- | :------------------------------------------------------------------ |
| `id`         | TEXT (PK) | IP Address (e.g., `192.168.1.5`) or Domain (`google.com`).          |
| `labels`     | TEXT      | JSON List `["Node"]`.                                               |
| `properties` | TEXT      | JSON Object. Contains `type` (`internal`/`external`), `risk_score`. |

### Table: `edges`

| Column       | Type      | Description                                                                            |
| :----------- | :-------- | :------------------------------------------------------------------------------------- |
| `source`     | TEXT (FK) | Origin IP.                                                                             |
| `target`     | TEXT (FK) | Destination IP/Domain.                                                                 |
| `relation`   | TEXT      | Usually `TALKS_TO`.                                                                    |
| `properties` | TEXT      | JSON Object. Contains `protocol` (`TCP`/`UDP`), `dst_port`, `byte_count`, `last_seen`. |

---

## 🔌 4. API Reference (The Back-End)

**Base URL:** `http://localhost:8000/api/v1`

### Policy / Alerting (`router/policy.py`)

- `GET /alerts`: Returns list of all active alerts.
- `POST /alerts`: Internal endpoint for Engine to push new alerts.
- `GET /blocked`: Returns list of currently blocked IPs (Feature 4).
- `POST /unblock/{ip}`: Manually unblock an IP.

### Discovery / Graph (`router/discovery.py`)

- `GET /nodes`: Returns all nodes for graph visualization.
- `GET /edges`: Returns all edges.

---

## 🎛️ 5. Configuration & CLI Flags

**Script:** `run_local.py`

| Flag         | Description                                                              | Default               |
| :----------- | :----------------------------------------------------------------------- | :-------------------- |
| `--live`     | **Live Mode.** Captures real traffic from NIC. Requires Npcap/libpcap.   | `False` (Demo Mode)   |
| `--inmemory` | **Ram Mode.** Does NOT use `shadow_hunter.db`. Graph is lost on restart. | `False` (Uses SQLite) |
| `--reset`    | **Fresh Start.** Wipes the existing DB before starting.                  | `False`               |

---

## 🛠️ 6. Troubleshooting Guide

- **"Address already in use"**:
  - Fix: Run `taskkill /F /IM python.exe` (Windows) or `pkill python` (Linux).
- **"Database is locked"**:
  - Fix: Ensure no other script (like `inspect_db.py`) creates a blocking write lock.
- **"Npcap not found"**:
  - Fix: Install Npcap in WinPcap compatibility mode (required for `--live`).

---

_Verified correct as of Phase 6 Implementation._
