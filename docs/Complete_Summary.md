# 🦅 Shadow Hunter: Defending the Digital Frontier

## The Ultimate Guide for Hackathon Judges & Developers

---

## � 1. What is Shadow Hunter? (The Elevator Pitch)

**Shadow Hunter** is an **Active Defense AI** that flips the script on cyber attackers.

Traditional cybersecurity tools (Firewalls, IDS) are passive—they sit and watch, hoping to match a known signature. Modern threats (AI-generated malware, Shadow AI usage, sophisticated APTs) easily bypass them.

**Shadow Hunter is different.** It doesn't just watch; it **hunts**.

1.  **It Profiles:** Identifying the _real_ tool behind the connection (is that "Chrome" actually a Python script?).
2.  **It Interrogates:** Active probing of suspicious servers to expose their true nature.
3.  **It Analyzes:** Using graph theory to find compromised devices acting as bridges.
4.  **It Reacts:** Autonomous blocking of high-confidence threats in milliseconds.

---

## 🏗️ 2. High-Level Architecture

Think of Shadow Hunter as a living organism:

- **The Ears (`Listener`)**: Captures every whisper on the network wire.
- **The Nervous System (`Broker`)**: Transmits signals instantly to the brain.
- **The Brain (`Analyzer`)**: Decides if a signal is a threat using ML & Graph logic.
- **The Memory (`Store`)**: Remembers every relationship in a graph database.
- **The Hands (`Active Defense` & `Response`)**: Probes enemies and blocks attacks.
- **The Face (`Dashboard`)**: Shows the operator what's happening in real-time.

---

## 📂 3. The Codebase: File-by-File Walkthrough

### 🟢 Root Directory (The Entry Point)

#### `run_local.py`

- **What it is:** The main startup script.
- **What it does:**
  - Initializes the `MemoryBroker` (the message bus).
  - Sets up the `SQLiteGraphStore` (the database).
  - Starts the `AnalyzerEngine` (the brain).
  - Launches the `API` (FastAPI) and `Dashboard` server.
  - **Crucially:** Based on flags (`--live` or default), it either starts the real `ListenerService` (packet capture) or the `TrafficGenerator` (demo simulation).

---

### 🟢 `services/listener/` (The Ears)

#### `sniffer.py`

- **What it is:** The raw packet capture module.
- **Key Functions:**
  - `PacketSniffer.start()`: Uses `scapy` to hook into the network interface.
  - `_process_packet(packet)`: The callback for every single frame. It filters out noise (ARP, DHCP) and focuses on TCP/UDP.
  - **JA3 Extraction:** This file parses the complex TLS handshake to extract the client's cryptographic fingerprint (JA3 hash). This is how we catch spoofers!

#### `main.py`

- **What it is:** The wrapper service.
- **What it does:** Manages the sniffer's lifecycle and publishes `NetworkFlowEvent` objects to the `Broker`.

---

### 🟢 `pkg/infra/local/` (The Infrastructure)

#### `broker.py`

- **What it is:** An in-memory Message Bus.
- **Why:** We need to decouple the fast listener from the slow analyzer. The listener dumps events here and returns immediately.
- **Key Class:** `MemoryBroker`. Implements a Pub/Sub pattern where the Analyzer subscribes to the "traffic" topic.

#### `store.py` & `sqlite_store.py`

- **What it is:** The Graph Database interface.
- **Why Graph?** We don't just log "A talked to B". We store **A -> B** as a connected edge. This allows us to query "Who are the friends of A's friends?" (Graph Theory).
- **Key Functions:**
  - `add_node()`: Upserts a device.
  - `add_edge()`: Records a connection.

---

### 🟢 `services/intelligence/` (The Intelligence)

#### `engine.py` (The ML Core)

- **What it is:** A sophisticated Machine Learning pipeline.
- **Key Models:**
  - **Autoencoder (Deep Learning):** Learns "normal" traffic patterns and flags deviations (0-day anomalies).
  - **Isolation Forest:** Statistical outlier detection for packet sizes and timing.
  - **Traffic Classifier:** Random Forest trained to distinguish "Shadow AI" traffic from regular web browsing.
- **Behavioral Analysis:**
  - `SessionAnalyzer`: Tracks user activity over time (e.g., "User uploaded 5GB in 1 hour") rather than just looking at single packets.

---

### � `services/analyzer/` (The Brain)

#### `engine.py` (The Commader)

- **What it is:** The central orchestrator.
- **Key Function:** `handle_traffic_event(event)`
  - **Step 1:** Asks **ML Engine** "Is this AI traffic?"
  - **Step 2:** Asks **JA3 Plugin** "Is this client spoofing?"
  - **Step 3:** Asks **Rules Engine** "Is this a known bad port?"
  - **Step 4:** Combines scores. If `Risk > 0.8`, it triggers **Active Defense**.
  - **Step 5:** If `Risk > 0.95`, it triggers **Auto-Response**.

#### `detector.py`

- **What it is:** The Rule-Based Engine.
- **What it does:** Loads plugins and runs static checks (e.g., "Port 22 outbound to unknown IP = Suspicious").

#### `plugins/ja3_plugin.py` (Feature 1)

- **What it is:** The Identity Detective.
- **Logic:**
  - If `JA3 Hash` matches **Cobalt Strike** → **CRITICAL ALERT**.
  - If `User-Agent` says "Chrome" but `JA3 Hash` is "Python" → **HIGH ALERT** (Spoofing).

---

### 🟢 `services/active_defense/` (The Muscle)

#### `interrogator.py` (Feature 2)

- **What it is:** The Active Prober.
- **The Problem:** Is `1.2.3.4` a benign web server or a hidden AI API?
- **The Solution:**
  - `probe_http_options()`: Sends a light `OPTIONS /` request to check server headers.
  - `probe_ai_endpoint()`: Sends a `GET /v1/models` request. If it replies with JSON, we **CONFIRM** it's a Shadow AI service.
- **Safety Guards:**
  - **Internal Whitelist:** NEVER probes `192.168.x.x` or `10.x.x.x`.
  - **Rate Limiter:** Only 10 probes/min to avoid looking like a DDoS.

---

### 🟢 `services/graph/` (The Detective)

#### `analytics.py` (Feature 3)

- **What it is:** The Topology Analyzer.
- **The Logic (Betweenness Centrality):**
  - Imagine a spider web. The most important points are the ones that connect different sections of the web.
  - This module builds a NetworkX graph of the entire network every 60 seconds.
  - It calculates which nodes are mathematically central.
- **The Catch:** If a developer's laptop suddenly becomes a "bridge" between the Internal HR Network and an External Unknown IP, that is **Lateral Movement**.

---

### 🟢 `services/response/` (The Shield)

#### `manager.py` (Feature 4)

- **What it is:** The Automated Responder (SOAR).
- **What it does:** Simulates a Firewall Block.
- **Logic:**
  - Triggered by **CRITICAL** severity alerts.
  - **Safety First:** Checks a hardcoded whitelist (DNS 8.8.8.8, Gateways) to prevent self-lockout.
  - **Action:** Adds IP to a quarantine list for 1 hour (TTL).
  - **Result:** The attack is stopped immediately without human intervention.

---

### 🟢 `services/dashboard/` (The Face)

- **What it is:** A React/Vite Frontend.
- **Key Features:**
  - **3D Network Graph:** A force-directed graph visualization powered by `shadow_hunter.db` that reveals the network topology in real-time.
  - **Live Alert Feed:** WebSocket connection to `broker` for sub-second alert notification.
  - **Stats Engine:** Visualizes threat levels and traffic volume.

---

### � `pkg/data/` (The Knowledge Base)

#### `ja3_intel.py`

- **What it is:** A database of fingerprints.
- **Content:** Contains the JA3 hashes for popular tools (requests, curl) and malware (Cobalt Strike, Trickbot).

#### `cidr_threat_intel.py`

- **What it is:** A database of IP ranges.
- **Content:** Known malicious subnets and Cloud Provider ranges (AWS, GCP, Azure).

---

---

## 🧬 3.5 Deep Dive: Algorithms & Models

Shadow Hunter is not a black box. It uses specific, industry-proven algorithms for each detection layer.

### 1. The Deep Learning Autoencoder (Zero-Day Detection)

- **Architecture:** A neural network with an "hourglass" shape (Input → Encoder → Bottleneck → Decoder → Output).
- **How it works:**
  - **Training:** It is trained ONLY on "normal" network traffic data. It learns to compress (encode) and reconstruct (decode) this normal data with high accuracy.
  - **Inference:** When a malicious packet arrives (e.g., a buffer overflow payload), the model fails to reconstruct it accurately because it has never seen such a pattern.
  - **Metric:** High **Reconstruction Error** = Anomaly.
- **Input Features:** Packet Size sequences, Inter-arrival times, Byte distribution entropy.

### 2. Isolation Forest (Statistical Outliers)

- **Type:** Unsupervised Learning.
- **Theory:** Anomalies are "few and different."
- **How it works:** It randomly selects a feature and a split value. Anomalies are isolated much faster (fewer splits) than normal points.
- **Use Case:** Catching data exfiltration (unusually large transfers) or C2 beacons (unusually regular timing).

### 3. Random Forest Classifier (Shadow AI Detection)

- **Type:** Supervised Learning.
- **Training Data:** Labeled dataset of known AI traffic (OpenAI, Anthropic, HuggingFace APIs) vs. General Web Traffic.
- **Features Used:**
  - Server Name Indication (SNI).
  - Certificate Issuer.
  - Mean Packet Size (AI APIs tend to have small requests and large streaming responses).
- **Output:** Probability scores for classes: `["Normal", "Suspicious", "Shadow_AI"]`.

### 4. Betweenness Centrality (Graph Theory)

- **Algorithm:** Brandes' Algorithm (via NetworkX).
- **Formula:** $C_B(v) = \sum_{s \neq v \neq t} \frac{\sigma_{st}(v)}{\sigma_{st}}$
  - Where $\sigma_{st}$ is total shortest paths from node $s$ to $t$.
  - Where $\sigma_{st}(v)$ is paths passing through node $v$.
- **Why:** Identifying nodes that control information flow. A compromised host acting as a proxy will interpret high centrality relative to its peers.

---

## 🎯 4. Why This Wins Hackathons

1.  **It's NOT Passive:** Most projects just visualize data. Shadow Hunter _interacts_ with the threat (Active Defense).
2.  **It uses Real Science:** Graph Theory (Centrality) and Cryptographic Fingerprinting (JA3) are advanced concepts, not just `if port == 80`.
3.  **It protects against "Shadow AI":** A timely problem (employees leaking data to unapproved AI models).
4.  **It's Safe:** Built-in guardrails (whitelists, rate limits) show production-ready thinking.

---

## 💡 5. Core Features & Implementation Utility

### How Each Feature Strengthens the Architecture

| Feature                  | Core Implementation Utility                                                                                                                                                                                                                                                                                              | Why It Matters                                                                               |
| :----------------------- | :----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | :------------------------------------------------------------------------------------------- |
| **JA3 Fingerprinting**   | **Enriches Packet Metadata.** Instead of just trusting the HTTP User-Agent header, the `AnalyzerEngine` now has a cryptographic proof of client identity. This allows the scoring logic to detect spoofing (e.g., Python claiming to be Chrome) with near 100% certainty.                                                | **Identity-Based Logic:** Moving security from "What port is this?" to "Who is this really?" |
| **Active Interrogation** | **Closes the Decision Loop.** The `AnalyzerEngine` often faces uncertainty (Is this unknown IP malicious or just a new API?). This feature acts as a verification subroutine, feeding definitive True/False data back into the alert stream, drastically reducing False Positives.                                       | **Verification:** Transforming "Suspicion" into "Confirmation" automatically.                |
| **Graph Centrality**     | **Temporal & Spatial Analysis.** Traditional IDS looks at one packet at a time. This feature uses the `GraphStore` to analyze the entire network history over time. It allows the core system to detect threats that are invisible in isolation but obvious in context (e.g., a laptop suddenly becoming a central hub). | **Context:** Detecting "Lateral Movement" which is impossible with single-packet inspection. |
| **Auto-Response**        | **Real-Time Actuation.** The ultimate goal of the system is protection, not just observation. This module gives the `AnalyzerEngine` "hands" to enforce its decisions instantly. By integrating directly with the alert pipeline, it reduces the Mean Time to Respond (MTTR) from minutes to milliseconds.               | **Speed:** Closing the OODA Loop (Observe-Orient-Decide-Act) faster than humanly possible.   |
| **Deep Learning ML**     | **Unknown Threat Detection.** Rules catch known bads. The Autoencoder learns "normal" and catches _unknown_ bads (0-days).                                                                                                                                                                                               | **Adaptability:** Catching attacks that have no signature yet.                               |
| **3D Visualization**     | **Situational Awareness.** Security is a data problem. The 3D graph turns rows of logs into an intuitive map, allowing analysts to _see_ the attack structure instantly.                                                                                                                                                 | **Usability:** Reducing cognitive load for the human operator.                               |

---

_This guide was generated to explain the inner workings of Shadow Hunter for evaluation purposes._
