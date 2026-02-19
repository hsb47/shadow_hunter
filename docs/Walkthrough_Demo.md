# 🎬 Shadow Hunter: Hackathon Demo Walkthrough

This guide provides a step-by-step script to demonstrate Shadow Hunter's capabilities during your presentation.

---

## 🏁 Phase 1: Preparation (Before the Demo)

1.  **Reset the Brain:**
    - Delete `shadow_hunter.db` to start with a fresh graph.
    - _Why:_ You want the judges to see the network being "discovered" live.

2.  **Start the Engine:**
    - Open Terminal 1:
      ```bash
      cd shadow_hunter
      python run_local.py
      ```
    - _Note:_ Ensure no other instance is running. If it fails, check if ports 8000/5173 use used.

3.  **Start the UI:**
    - Open Terminal 2:
      ```bash
      cd shadow_hunter/services/dashboard
      npm run dev
      ```
    - Open Browser: `http://localhost:5173`

---

## 🎭 Phase 2: The Core Demo (3 Minutes)

### Step 1: Visualizing the Network (0:00 - 0:45)

- **Action:** Open the **Dashboard**. Point to the 3D Graph.
- **Narrative:**
  > "Standard tools give you text logs. Shadow Hunter gives you a living map. Using Graph Theory, we visualize every connection in real-time."
- **Visual:** You will see nodes popping up as the simulation traffic flows.

### Step 2: Detecting "Shadow AI" (0:45 - 1:30)

- **Context:** The simulation will generate traffic to an external AI API (e.g., `api.openai.com` or a simulated unknown IP).
- **Action:** Click the **Alerts** tab. Wait for a "Shadow AI Usage" alert.
- **Narrative:**
  > "Our ML engine analyzes packet size and timing. Even though this traffic is encrypted (HTTPS), we can classify it as 'Shadow AI' with 90% confidence."

### Step 3: Active Defense in Action (1:30 - 2:15)

- **Action:** Switch to the **Terminal (Backend Logs)**.
- **Highlight:** Look for the cyan/green log lines:
  ```
  [ACTIVE DEFENSE] 🛡️ Probing suspicious host...
  [ACTIVE DEFENSE] ✅ Confirmed AI Service via Probe
  ```
- **Narrative:**
  > "Here is the game-changer. Instead of just guessing, Shadow Hunter _actively interrogates_ the destination. It sent a probe, confirmed it's an AI API, and enriched the alert instantly."

### Step 4: Graph Centrality & Auto-Block (2:15 - 3:00)

- **Context:** The simulation creates a "Lateral Movement" scenario where a compromised laptop scans internal servers.
- **Action:** Back to Dashboard. Look for a **CRITICAL** alert: _"Lateral Movement Detected (High Centrality)"_.
- **Narrative:**
  > "This device is acting as a bridge. Our Graph Centrality algorithm flagged it. Because the confidence is Critical, watch what happens..."
- **Visual:** The node turns **RED** on the graph. A "Blocking IP" notification appears.
- **Closing:**
  > "Shadow Hunter autonomously neutralized the threat in milliseconds. No human intervention required."

---

## 🧪 Phase 3: Validation (Q&A Backup)

If judges ask "Is this real?", show them:

1.  **The Database:** Run `python inspect_db.py` to show the raw stored graph.
2.  **The Code:** Open `services/intelligence/engine.py` to show the Random Forest & Autoencoder models.
3.  **The Verification:** Open `test_interrogator.py` or verification logs to prove the logic holds up.

---

## ⚠️ Troubleshooting

- **"Port in use" error:** Close all terminals and restart.
- **No alerts?** The simulation relies on randomness. Wait 1-2 minutes or restart `run_local.py`.
- **UI Empty?** Refresh the page. Ensure backend is running on `localhost:8000`.

Good luck! 🚀
