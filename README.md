# 🕵️‍♂️ Shadow Hunter

**Real-Time Shadow AI Detection & Monitoring Platform**

> **What is Shadow AI?**  
> "Shadow AI" refers to the unsanctioned use of generative AI tools (ChatGPT, Claude, Copilot, etc.) by employees. While it boosts productivity, it introduces critical risks: **Data Exfiltration** (PII/Secrets), **Compliance Violations** (GDPR/HIPAA), and **Intellectual Property Leakage**.

**Shadow Hunter** is an enterprise-grade network monitoring solution designed to detect, visualize, and manage Shadow AI usage in real-time. It operates passively, analyzing network traffic to identify AI service connections without requiring invasive endpoint agents.

---

## 🚀 Key Features

- **Hybrid Monitoring Engine**:
  - **Live Mode**: Captures real network traffic using `Npcap` / `Scapy`.
  - **Demo Mode**: Simulates realistic enterprise traffic with 5 distinct employee personas.
- **Dual-Layer Detection**:
  - **Rule-Based**: Instant identification of **100+ AI domains** (OpenAI, Anthropic, HuggingFace, etc.) via a curated whitelist.
  - **ML-Powered Anomaly Detection**: Isolation Forest & Random Forest models detect **unknown** or **encrypted** AI traffic anomalies rooted in packet behavior (size, frequency, duration).
- **Intelligent Whitelisting**: Automatically filters out noise (Multicast, mDNS, UPnP, Internal-to-Internal) to focus on genuine external threats.
- **Real-Time Visualization**:
  - Interactive **Force-Directed Graph** of your network's AI footprint.
  - **Traffic Analytics** breakdown (AI vs. Normal, Protocol Distribution).
- **Actionable Intelligence**:
  - **Risk Scoring** (0-100) for every internal IP.
  - **Smart Alerts** enriched with AI Categories (LLM, Code Assistant, Image Gen).
  - **Browser Notifications** for High-Severity incidents.

---

## 🏗️ Architecture

Shadow Hunter follows a modern, scalable data pipeline architecture designed for high-throughput network analysis.

```mermaid
graph TB
    subgraph "Layer 1: Traffic Collection"
        A[Enterprise Network] -->|Packets/Flows| B(Traffic Sniffer / Simulator)
        subgraph "Sources"
            A1[User Devices]
            A2[Servers/VMs]
            A3[Kubernetes Clusters]
        end
        A1 --> A
        A2 --> A
        A3 --> A
    end

    subgraph "Layer 2: Detection & Processing"
        B --> C{Broker / Queue}
        C --> D[Shadow Hunter Analyzer]

        subgraph "Analyzer Modules"
            D1[Protocol Decoder (DPI)]
            D2[Whitelisting Engine]
            D3[Rule Engine (AI Domains)]
            D4[ML Inference (Isolation Forest)]
        end

        D --> D1 --> D2 --> D3 --> D4
        D --> E[(Graph Database)]
    end

    subgraph "Layer 3: Visualization & Response"
        D --> F[API Service (FastAPI)]
        F --> G[Web Dashboard (React)]
        F --> H[Alert System]

        subgraph "Dashboard Views"
            G1[Live Graph]
            G2[Traffic Analytics]
            G3[Intel Feed]
        end

        G --> G1
        G --> G2
        G --> G3
    end

    classDef layer fill:#f9f,stroke:#333,stroke-width:2px;
    class A,B,C,D,E,F,G,H layer;
```

---

## 🛠️ Installation & Setup

### Prerequisites

- **Python 3.10+**
- **Node.js 18+**
- **Npcap** (Windows) or `libpcap` (Linux/Mac) for Live Mode capture.

### 1. Clone & Install Dependencies

```bash
# Clone the repository
git clone https://github.com/yourusername/shadow-hunter.git
cd shadow-hunter

# Install Python dependencies
pip install -r requirements.txt

# Install Frontend dependencies
cd services/dashboard
npm install
cd ../..
```

### 2. Run the Platform

You can run Shadow Hunter in two modes:

#### 🅰️ Demo Mode (Simulation)

Perfect for testing and demonstrations. Generates safe, simulated traffic.

```bash
# Terminal 1: Backend
python run_local.py

# Terminal 2: Frontend
cd services/dashboard
npm run dev
```

#### 🅱️ Live Mode (Real Capture)

Monitors your actual network interface. **Requires Administrator privileges.**

```bash
# Terminal 1: Backend (Run as Admin)
python run_local.py --live

# Terminal 2: Frontend
cd services/dashboard
npm run dev
```

---

## 📊 Dashboard Guide

1.  **Dashboard Tab**: Shows the real-time **Network Graph**.
    - Types: 🔵 Internal, 🟢 External (Safe), 🔴 Shadow AI.
    - Click any node to see detailed connections.
2.  **Network Tab**:
    - **Node Inventory**: List of all discovered devices.
    - **Traffic Analytics**: Charts showing protocol usage and top destinations.
    - **Search**: Filter nodes by IP or name.
    - **Export**: Download inventory as CSV.
3.  **Alerts Tab**:
    - Live feed of detected threats.
    - **High Severity**: Known AI domains, Data Exfiltration > 50MB.
    - **Medium/Low**: Suspicious ports, Anomalous traffic patterns.
    - **Export**: Download alert history as CSV.

---

## 🛡️ Technology Stack

- **Backend**: Python, FastAPI, Scapy (Packet Capture), Scikit-Learn (ML), NetworkX (Graph Theory).
- **Frontend**: React, Vite, Tailwind CSS, Lucide Icons.
- **Visualization**: Cytoscape.js (Graph), Recharts (Analytics).
- **Deployment**: Docker (Optional), Local Process.

---

## ⚠️ Disclaimer

_Shadow Hunter is a Proof-of-Concept (PoC) security tool. Ensure you have authorization before monitoring network traffic on any network you do not own._
