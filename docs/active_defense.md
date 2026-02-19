# Shadow Hunter Phase 6: Active Defense User Guide

This guide explains the four new **Active Defense** capabilities added in Phase 6. These features transform Shadow Hunter from a passive monitoring tool into an active security system capable of detecting sophisticated threats and responding automatically.

---

## 🛡️ Feature 1: JA3 Client Fingerprinting

**"The Digital Fingerprint Scanner"**

### What is it?

Every SSL/TLS client (browser, script, malware) has a unique "handshake" signature called a JA3 hash. This signature remains the same even if the client lies about its identity in the User-Agent header.

### What is it used for?

1.  **Detecting Spoofing:** Identifying Python scripts pretending to be "Chrome".
2.  **Catching Malware:** Flagging known attack tools like Cobalt Strike, Metasploit, or Mimikatz.
3.  **Spotting Shadow IT:** Finding developers using unauthorized scripting tools (`curl`, `wget`, `scrapy`) against production APIs.

### How to use it?

- **Automatic:** It runs passively on all encrypted traffic.
- **Alerts:** You will see alerts like:
  - `🎭 IDENTITY SPOOFING: UA claims Chrome but JA3 is Python requests`
  - `🔴 ATTACK TOOL DETECTED: Cobalt Strike Beacon`
- **Dashboard:** Alerts will now contain a `ja3_intel` section with client details.

---

## 🔍 Feature 2: Active Interrogation

**"The Security Guard at the Door"**

### What is it?

When Shadow Hunter sees a highly suspicious connection (e.g., to an unknown external IP with a high risk score), it sends a controlled "probe" to that destination to verify its nature.

### What is it used for?

1.  **Verifying Shadow AI:** Confirming if `1.2.3.4` is actually an undocumented LLM API by checking for `/v1/models`.
2.  **Reducing False Positives:** Distinguishing between a generic web server and a specialized AI service.
3.  **Gathering Intel:** Collecting server headers and capabilities without exposing sensitive data.

### How to use it?

- **Automatic:** Triggers only on **CRITICAL** or **HIGH** severity alerts.
- **Safety:**
  - Never probes internal IPs (e.g., `192.168.x.x`).
  - Rate-limited to 10 probes/minute.
  - 5-minute cooldown per target.
- **Alerts:** You'll see `[Active probe CONFIRMED AI service]` appended to alert descriptions.

---

## 🕸️ Feature 3: Graph Centrality

**"The Spider in the Web"**

### What is it?

Analyzes the shape (topology) of your network traffic graph to find "bridge" nodes—devices that connect two otherwise separated groups of computers (e.g., Internal Engineering ↔ External Unknowns).

### What is it used for?

1.  **Detecting Lateral Movement:** Identifying a compromised laptop acting as a gateway for an attacker to move deeper into the network.
2.  **Finding Pivots:** Spotting the single point of failure or compromise in a complex network.
3.  **Anomalous Behavior:** Detecting a device that suddenly starts talking to everyone (star topology).

### How to use it?

- **Automatic:** Runs every 60 seconds.
- **Alerts:** Look for "Graph Centrality Analysis" alerts:
  - `HIGH RISK: Node 192.168.1.50 bridges internal and external networks`
- **Visual:** In the Graph View, high-centrality nodes are key choke points.

---

## 🤖 Feature 4: Auto-Response (SOAR)

**"The Automated Bouncer"**

### What is it?

A Security Orchestration, Automation, and Response (SOAR) module that automatically blocks IP addresses that trigger **CRITICAL** severity alerts.

### What is it used for?

1.  **Stopping Attacks Fast:** Blocking C2 channels or data exfiltration instantly (milliseconds vs. minutes/hours for humans).
2.  **Containing Damage:** Isolating a compromised host before it can infect others.
3.  **Reducing Analyst Fatigue:** Handling obvious threats automatically so you can focus on complex ones.

### How to use it?

- **Automatic:** Triggers on **CRITICAL** alerts (e.g., known malware, massive data exfiltration).
- **Configuration:**
  - **Whitelist:** Never blocks DNS (8.8.8.8), gateways, or localhost.
  - **TTL:** Blocks expire automatically after 1 hour (configurable).
- **Dashboard:** A new "Auto-Response" event type will appear in the feed showing `ACTION: BLOCK`.

---

## Summary of Operations

| Feature           | Trigger          | Action               | Outcome                       |
| :---------------- | :--------------- | :------------------- | :---------------------------- |
| **JA3**           | Every SSL Packet | Match Hash           | `spoofing` or `malware` alert |
| **Interrogation** | High Risk Alert  | Send HTTP Probe      | Confirm AI Service            |
| **Graph**         | Every 60s        | Calculate Centrality | `lateral movement` alert      |
| **Auto-Response** | Critical Alert   | Block IP             | Attack Stopped                |
