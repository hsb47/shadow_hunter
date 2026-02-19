# Real-World Verification Guide

This guide explains how to manually test Shadow Hunter by generating real network traffic and verifying it on the dashboard.

## Prerequisites

1.  **Windows with Npcap:** Ensure you have [Npcap](https://npcap.com/) installed (usually installed with Wireshark).
    - _Note:_ Allows Python to capture packets on Windows.
2.  **Administrator Privileges:** You may need to run the terminal as Administrator for raw socket access.

## Step 1: Start the Backend (No Simulation)

We want to see _real_ traffic, so do **not** use the `--simulate` flag.

1.  Open a terminal in `shadow_hunter/`.
2.  Run:
    ```bash
    python run_local.py
    ```
3.  You should see logs indicating:
    - `Starting packet capture on interface: ALL`
    - `Packet capture started.`

## Step 2: Start the Dashboard

1.  Open a new terminal in `shadow_hunter/services/dashboard/`.
2.  Run:
    ```bash
    npm run dev
    ```
3.  Open `http://localhost:5173` in your browser.

## Step 3: Generate "Shadow AI" Traffic

Now, act like a user bypassing corporate policy.

1.  **Open a Web Browser.**
2.  **Visit Known AI Sites:**
    - Go to `https://chatgpt.com`
    - Go to `https://claude.ai`
    - Go to `https://huggingface.co`
3.  **Generate API Traffic (Optional):**
    - Open a terminal (Git Bash or PowerShell).
    - Run: `curl -I https://api.openai.com`
    - Run: `nslookup openai.com`

## Step 4: Verify on Dashboard

Watch the Dashboard while you browse.

### What to Expect:

1.  **New Nodes:**
    - You should see new nodes appear with names like `openai.com`, `chatgpt.com`, or `TargetIP:443`.
    - **Color Coding:**
      - **Green:** External Service (General Internet).
      - **Red (Dashed):** Shadow AI / Known AI Domain (if detected by DPI).

2.  **Alerts Panel:**
    - Look for an alert: **"Known AI Service Accessed: openai.com"**
    - Severity: **HIGH** or **MEDIUM**.

### Troubleshooting

- **No Traffic Showing?**
  - The `sniffer.py` might be listening on the wrong interface. Set `SH_CAPTURE_INTERFACE` env var to your active Wi-Fi/Ethernet adapter name (e.g., `Wi-Fi` or `Ethernet0`).
  - _Windows:_ `set SH_CAPTURE_INTERFACE=Wi-Fi` then run `python run_local.py`.
- **"Unknown" Nodes only?**
  - HTTPS traffic is encrypted. We rely on **TLS SNI** (Server Name Indication) to see the domain.
  - If SNI parsing fails, you might just see the destination IP (e.g., `104.18.x.x`).
  - Try `nslookup` (DNS) traffic; it is unencrypted and easier to detect.
