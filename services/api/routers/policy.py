from fastapi import APIRouter
from pydantic import BaseModel
from typing import List, Optional
import uuid

router = APIRouter()

# In-memory alert store (shared across the app)
_alerts_store: List[dict] = []

# ── Policy Rules Store ──
_policy_rules: List[dict] = [
    {
        "id": "rule-default-1",
        "name": "Block ChatGPT for Finance",
        "action": "block",
        "service": "chatgpt",
        "department": "Finance",
        "severity": "HIGH",
        "enabled": True,
        "description": "Prevent Finance department from accessing ChatGPT to protect financial data",
    },
    {
        "id": "rule-default-2",
        "name": "Allow Copilot for Engineering",
        "action": "allow",
        "service": "copilot",
        "department": "Engineering",
        "severity": "LOW",
        "enabled": True,
        "description": "Engineering team is approved to use GitHub Copilot for development",
    },
    {
        "id": "rule-default-3",
        "name": "Monitor Midjourney Usage",
        "action": "monitor",
        "service": "midjourney",
        "department": "All",
        "severity": "MEDIUM",
        "enabled": True,
        "description": "Log and monitor all Midjourney image generation activity",
    },
    {
        "id": "rule-default-4",
        "name": "Block Claude for Legal",
        "action": "block",
        "service": "claude",
        "department": "Legal",
        "severity": "HIGH",
        "enabled": False,
        "description": "Restrict Legal department from using Claude to prevent PII exposure",
    },
]

def add_alert(alert: dict):
    """Called by the analyzer to push alerts."""
    _alerts_store.append(alert)
    # Keep last 100 alerts
    if len(_alerts_store) > 100:
        _alerts_store.pop(0)

def check_policy(service: str, source: str) -> Optional[dict]:
    """Check if any enabled policy rule matches the given service."""
    service_lower = service.lower()
    for rule in _policy_rules:
        if rule["enabled"] and rule["service"].lower() in service_lower:
            return rule
    return None

def get_alerts_store() -> List[dict]:
    return _alerts_store

@router.get("/alerts")
async def get_alerts():
    """
    Get active security alerts from the live store.
    """
    return _alerts_store

@router.post("/scan")
async def trigger_scan():
    """
    Manually trigger an active interrogation scan.
    """
    return {"status": "scan_initiated", "job_id": "job-123"}

# ── Policy Rules CRUD ──

@router.get("/rules")
async def get_rules():
    """Get all policy rules."""
    return _policy_rules

@router.post("/rules")
async def create_rule(rule: dict):
    """Create a new policy rule."""
    new_rule = {
        "id": f"rule-{uuid.uuid4().hex[:8]}",
        "name": rule.get("name", "Unnamed Rule"),
        "action": rule.get("action", "monitor"),
        "service": rule.get("service", ""),
        "department": rule.get("department", "All"),
        "severity": rule.get("severity", "MEDIUM"),
        "enabled": rule.get("enabled", True),
        "description": rule.get("description", ""),
    }
    _policy_rules.append(new_rule)
    return new_rule

@router.put("/rules/{rule_id}/toggle")
async def toggle_rule(rule_id: str):
    """Toggle a rule's enabled state."""
    for rule in _policy_rules:
        if rule["id"] == rule_id:
            rule["enabled"] = not rule["enabled"]
            return rule
    return {"error": "Rule not found"}

@router.delete("/rules/{rule_id}")
async def delete_rule(rule_id: str):
    """Delete a policy rule."""
    global _policy_rules
    _policy_rules = [r for r in _policy_rules if r["id"] != rule_id]
    return {"status": "deleted", "id": rule_id}

@router.get("/killchain")
async def get_killchain():
    """
    Classify alerts into MITRE ATT&CK kill chain stages.
    """
    alerts = _alerts_store

    stages = {
        "reconnaissance": {
            "label": "Reconnaissance",
            "description": "Scanning and probing for AI services",
            "keywords": ["scan", "probe", "discover", "dns", "lookup", "resolve"],
            "alerts": [],
        },
        "initial_access": {
            "label": "Initial Access",
            "description": "First connection to unauthorized AI service",
            "keywords": ["shadow ai", "unauthorized", "first seen", "new connection", "unknown service"],
            "alerts": [],
        },
        "execution": {
            "label": "Execution",
            "description": "Active usage of AI service — queries, uploads, prompts",
            "keywords": ["chatgpt", "claude", "copilot", "gemini", "midjourney", "ai service", "query", "prompt"],
            "alerts": [],
        },
        "exfiltration": {
            "label": "Exfiltration",
            "description": "Data leaving the network to AI services",
            "keywords": ["exfiltration", "upload", "large transfer", "data leak", "pii", "api key", "sensitive"],
            "alerts": [],
        },
        "impact": {
            "label": "Impact",
            "description": "Policy violations, compliance breaches, high-severity events",
            "keywords": ["violation", "breach", "critical", "block", "policy"],
            "alerts": [],
        },
    }

    for alert in alerts:
        desc = (alert.get("description", "") or "").lower()
        severity = alert.get("severity", "LOW")
        classified = False

        # Classify by keyword matching (priority order)
        for stage_id in ["impact", "exfiltration", "execution", "initial_access", "reconnaissance"]:
            stage = stages[stage_id]
            if any(kw in desc for kw in stage["keywords"]):
                stages[stage_id]["alerts"].append({
                    "id": alert.get("id"),
                    "description": alert.get("description"),
                    "severity": severity,
                    "source": alert.get("source"),
                    "target": alert.get("target"),
                    "timestamp": alert.get("timestamp"),
                })
                classified = True
                break

        # Fallback: classify by severity
        if not classified:
            if severity == "HIGH":
                stages["impact"]["alerts"].append({
                    "id": alert.get("id"),
                    "description": alert.get("description"),
                    "severity": severity,
                    "source": alert.get("source"),
                    "target": alert.get("target"),
                    "timestamp": alert.get("timestamp"),
                })
            elif severity == "MEDIUM":
                stages["execution"]["alerts"].append({
                    "id": alert.get("id"),
                    "description": alert.get("description"),
                    "severity": severity,
                    "source": alert.get("source"),
                    "target": alert.get("target"),
                    "timestamp": alert.get("timestamp"),
                })
            else:
                stages["reconnaissance"]["alerts"].append({
                    "id": alert.get("id"),
                    "description": alert.get("description"),
                    "severity": severity,
                    "source": alert.get("source"),
                    "target": alert.get("target"),
                    "timestamp": alert.get("timestamp"),
                })

    # Build response
    result = []
    stage_order = ["reconnaissance", "initial_access", "execution", "exfiltration", "impact"]
    active_chain = 0
    for sid in stage_order:
        s = stages[sid]
        count = len(s["alerts"])
        if count > 0:
            active_chain += 1
        result.append({
            "id": sid,
            "label": s["label"],
            "description": s["description"],
            "count": count,
            "alerts": s["alerts"][:10],  # top 10 per stage
            "active": count > 0,
        })

    return {
        "stages": result,
        "total_alerts": len(alerts),
        "active_stages": active_chain,
        "chain_completion": round((active_chain / 5) * 100),
    }

@router.get("/compliance")
async def get_compliance():
    """
    Score compliance against SOC2, GDPR, HIPAA based on Shadow AI usage patterns.
    """
    from collections import defaultdict

    alerts = _alerts_store
    total = len(alerts)

    # Count violations per framework
    shadow_ai_count = sum(1 for a in alerts if "shadow ai" in (a.get("description", "") or "").lower())
    high_sev = sum(1 for a in alerts if a.get("severity") == "HIGH")
    dlp_risk = sum(1 for a in alerts if any(kw in (a.get("description", "") or "").lower() for kw in ["pii", "data leak", "exfiltration", "api key"]))
    unauth_count = sum(1 for a in alerts if any(kw in (a.get("description", "") or "").lower() for kw in ["unauthorized", "shadow", "unknown"]))

    # Blocked by policy
    blocked_rules = sum(1 for r in _policy_rules if r["enabled"] and r["action"] == "block")

    frameworks = [
        {
            "id": "soc2",
            "name": "SOC 2",
            "description": "Service Organization Control — data security & availability",
            "checks": [
                {"name": "Unauthorized AI Access Control", "status": "fail" if shadow_ai_count > 3 else "warn" if shadow_ai_count > 0 else "pass", "detail": f"{shadow_ai_count} Shadow AI events detected"},
                {"name": "Data Loss Prevention", "status": "fail" if dlp_risk > 2 else "warn" if dlp_risk > 0 else "pass", "detail": f"{dlp_risk} potential DLP incidents"},
                {"name": "Access Monitoring", "status": "pass" if total > 0 else "warn", "detail": f"Monitoring active — {total} events captured"},
                {"name": "Policy Enforcement", "status": "pass" if blocked_rules >= 2 else "warn" if blocked_rules > 0 else "fail", "detail": f"{blocked_rules} blocking rules active"},
            ],
        },
        {
            "id": "gdpr",
            "name": "GDPR",
            "description": "General Data Protection Regulation — EU personal data privacy",
            "checks": [
                {"name": "PII Protection", "status": "fail" if dlp_risk > 1 else "warn" if dlp_risk > 0 else "pass", "detail": f"{dlp_risk} PII exposure risks"},
                {"name": "Data Processing Records", "status": "pass", "detail": "Alert logging active"},
                {"name": "Right to Erasure Controls", "status": "warn", "detail": "Manual review recommended"},
                {"name": "Cross-border Transfer", "status": "fail" if shadow_ai_count > 2 else "warn" if shadow_ai_count > 0 else "pass", "detail": f"{shadow_ai_count} transfers to external AI services"},
            ],
        },
        {
            "id": "hipaa",
            "name": "HIPAA",
            "description": "Health Insurance Portability & Accountability — protected health info",
            "checks": [
                {"name": "PHI Safeguards", "status": "fail" if high_sev > 3 else "warn" if high_sev > 0 else "pass", "detail": f"{high_sev} high-severity events"},
                {"name": "Access Controls", "status": "pass" if blocked_rules > 0 else "fail", "detail": f"{blocked_rules} access control policies"},
                {"name": "Audit Trail", "status": "pass", "detail": "Full event logging enabled"},
                {"name": "Breach Notification", "status": "pass" if total > 0 else "warn", "detail": "Real-time alerting active"},
            ],
        },
    ]

    # Calculate scores
    for fw in frameworks:
        checks = fw["checks"]
        score = 0
        for c in checks:
            if c["status"] == "pass":
                score += 100
            elif c["status"] == "warn":
                score += 60
            # fail = 0
        fw["score"] = round(score / len(checks)) if checks else 100
        fw["pass_count"] = sum(1 for c in checks if c["status"] == "pass")
        fw["warn_count"] = sum(1 for c in checks if c["status"] == "warn")
        fw["fail_count"] = sum(1 for c in checks if c["status"] == "fail")

    overall = round(sum(f["score"] for f in frameworks) / len(frameworks)) if frameworks else 100

    return {
        "frameworks": frameworks,
        "overall_score": overall,
        "total_checks": sum(len(f["checks"]) for f in frameworks),
        "violations": sum(f["fail_count"] for f in frameworks),
    }


@router.get("/briefing")
async def get_briefing():
    """
    Generate a natural language executive threat briefing.
    """
    from collections import Counter
    from datetime import datetime

    alerts = _alerts_store
    total = len(alerts)

    if total == 0:
        return {
            "paragraphs": [
                {"type": "status", "text": "No security events have been recorded yet. The monitoring system is active and scanning for Shadow AI activity, unauthorized data transfers, and policy violations."},
            ],
            "generated_at": datetime.now().isoformat(),
            "period": "Current Session",
            "threat_level": "LOW",
        }

    # Analyze data
    sev_counts = Counter(a.get("severity", "LOW") for a in alerts)
    sources = Counter(a.get("source", "unknown") for a in alerts)
    targets = Counter(a.get("target", "unknown") for a in alerts)
    shadow_ai = sum(1 for a in alerts if "shadow ai" in (a.get("description", "") or "").lower())
    top_source = sources.most_common(1)[0] if sources else ("unknown", 0)
    top_target = targets.most_common(1)[0] if targets else ("unknown", 0)

    high = sev_counts.get("HIGH", 0)
    medium = sev_counts.get("MEDIUM", 0)
    low = sev_counts.get("LOW", 0)

    # Determine threat level
    if high > 5 or shadow_ai > 10:
        threat = "CRITICAL"
    elif high > 2 or shadow_ai > 5:
        threat = "HIGH"
    elif high > 0 or medium > 3:
        threat = "ELEVATED"
    else:
        threat = "LOW"

    paragraphs = []

    # Overview
    paragraphs.append({
        "type": "overview",
        "title": "Situation Overview",
        "text": f"During the current monitoring session, Shadow Hunter has analyzed and classified {total} security events. The system has identified {high} high-severity incidents, {medium} medium-severity events, and {low} low-severity observations. The current threat level is assessed as {threat}.",
    })

    # Shadow AI
    if shadow_ai > 0:
        paragraphs.append({
            "type": "shadow_ai",
            "title": "Shadow AI Activity",
            "text": f"{shadow_ai} instances of unauthorized AI service usage have been detected across the network. {'This represents a significant compliance risk requiring immediate investigation.' if shadow_ai > 5 else 'These events are being monitored and correlated for pattern analysis.'}",
        })

    # Top threat actor
    paragraphs.append({
        "type": "actor",
        "title": "Primary Threat Actor",
        "text": f"The most active source IP is {top_source[0]} with {top_source[1]} associated events. The primary target destination is {top_target[0]}, receiving traffic from {targets[top_target[0]]} connections. {'This concentrated activity pattern suggests targeted data exfiltration.' if top_source[1] > 5 else 'Activity levels are within normal parameters but warrant continued monitoring.'}",
    })

    # Recommendations
    recs = []
    if high > 0:
        recs.append("Immediately investigate all HIGH-severity alerts and isolate compromised endpoints")
    if shadow_ai > 0:
        recs.append("Review and enforce Shadow AI usage policies across all departments")
    if len(sources) > 3:
        recs.append(f"Audit the {len(sources)} unique source IPs for unauthorized access patterns")
    recs.append("Continue real-time monitoring and ensure DLP policies are enabled")

    paragraphs.append({
        "type": "recommendations",
        "title": "Recommended Actions",
        "items": recs,
    })

    return {
        "paragraphs": paragraphs,
        "generated_at": datetime.now().isoformat(),
        "period": "Current Session",
        "threat_level": threat,
        "stats": {
            "total_events": total,
            "high_severity": high,
            "shadow_ai": shadow_ai,
            "unique_sources": len(sources),
            "unique_targets": len(targets),
        },
    }

@router.get("/dlp")
async def get_dlp_incidents():
    """
    Analyze alerts for DLP-relevant incidents.
    Detects potential data exfiltration to AI services.
    """
    import re
    from datetime import datetime

    alerts = _alerts_store
    incidents = []

    # DLP patterns to check
    dlp_patterns = {
        "pii_exposure": {
            "label": "PII Exposure Risk",
            "description": "Outbound traffic to AI service may contain personally identifiable information",
            "severity": "HIGH",
            "keywords": ["shadow ai", "chatgpt", "claude", "gemini", "perplexity"],
        },
        "api_key_leak": {
            "label": "API Key Leak Risk",
            "description": "Large outbound payload to AI coding assistant may contain API keys or credentials",
            "severity": "HIGH",
            "keywords": ["copilot", "cursor", "replit", "code ai"],
        },
        "data_exfiltration": {
            "label": "Data Exfiltration",
            "description": "Significant data volume transferred to external AI service",
            "severity": "HIGH",
            "keywords": [],
        },
        "code_snippet": {
            "label": "Code Snippet Upload",
            "description": "Source code may have been uploaded to AI coding tool",
            "severity": "MEDIUM",
            "keywords": ["copilot", "cursor", "replit", "code"],
        },
        "document_upload": {
            "label": "Document Upload Risk",
            "description": "Document content may have been shared with external AI service",
            "severity": "MEDIUM",
            "keywords": ["chatgpt", "claude", "gemini", "anthropic"],
        },
    }

    for alert in alerts:
        desc = alert.get("description", "").lower()
        target = alert.get("target", "").lower()
        bytes_sent = alert.get("bytes_sent", 0) or 0
        severity = alert.get("severity", "LOW")

        matched_patterns = []

        for pattern_id, pattern in dlp_patterns.items():
            matched = False

            # Check keywords
            if pattern["keywords"]:
                if any(kw in desc or kw in target for kw in pattern["keywords"]):
                    matched = True

            # Check data exfiltration by bytes
            if pattern_id == "data_exfiltration" and bytes_sent > 5000:
                if "shadow ai" in desc or severity == "HIGH":
                    matched = True

            if matched:
                matched_patterns.append(pattern_id)

        if matched_patterns:
            primary = matched_patterns[0]
            p = dlp_patterns[primary]
            incidents.append({
                "id": f"dlp-{alert.get('id', 'unknown')}",
                "alert_id": alert.get("id"),
                "type": primary,
                "label": p["label"],
                "description": p["description"],
                "severity": p["severity"],
                "source": alert.get("source", "unknown"),
                "target": alert.get("target", "unknown"),
                "bytes_sent": bytes_sent,
                "timestamp": alert.get("timestamp"),
                "matched_patterns": matched_patterns,
                "original_alert": alert.get("description", ""),
            })

    # Summary stats
    total = len(incidents)
    high = sum(1 for i in incidents if i["severity"] == "HIGH")
    types = {}
    for i in incidents:
        types[i["type"]] = types.get(i["type"], 0) + 1

    incidents.sort(key=lambda x: x.get("timestamp", ""), reverse=True)

    return {
        "incidents": incidents[:50],
        "summary": {
            "total_incidents": total,
            "high_severity": high,
            "types": types,
        },
    }

@router.get("/timeline")
async def get_timeline():
    """
    Returns alerts bucketed by minute for time-series chart,
    plus unique filter values for protocols and source IPs.
    """
    from collections import Counter, defaultdict
    from datetime import datetime

    alerts = _alerts_store

    # Bucket alerts by minute
    buckets = defaultdict(lambda: {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "total": 0})
    protocols = set()
    sources = set()

    for a in alerts:
        ts = a.get("timestamp", "")
        sev = a.get("severity", "LOW")
        proto = a.get("protocol", "")
        src = a.get("source", "")

        if proto:
            protocols.add(proto)
        if src:
            sources.add(src)

        # Bucket key: HH:MM
        try:
            dt = datetime.fromisoformat(ts)
            key = dt.strftime("%H:%M")
        except Exception:
            key = "??:??"

        buckets[key][sev] += 1
        buckets[key]["total"] += 1

    # Sort buckets by time
    sorted_buckets = [
        {"time": k, **v}
        for k, v in sorted(buckets.items())
    ]

    return {
        "buckets": sorted_buckets,
        "filters": {
            "protocols": sorted(protocols),
            "sources": sorted(sources),
        },
        "total_alerts": len(alerts),
    }

@router.get("/sessions")
async def get_sessions():
    """
    Group alerts into sessions by source IP within a 5-minute window.
    Returns sessions with risk scores, activity timelines, and summaries.
    """
    from collections import defaultdict
    from datetime import datetime, timedelta

    alerts = sorted(_alerts_store, key=lambda a: a.get("timestamp", ""))
    
    # Group by source IP
    by_source = defaultdict(list)
    for a in alerts:
        by_source[a.get("source", "unknown")].append(a)
    
    sessions = []
    session_id = 0
    
    for source, source_alerts in by_source.items():
        # Split into sessions: gap > 5 minutes = new session
        current_session = []
        for a in source_alerts:
            try:
                ts = datetime.fromisoformat(a.get("timestamp", ""))
            except Exception:
                ts = datetime.now()
            
            if current_session:
                last_ts = current_session[-1]["_ts"]
                if (ts - last_ts).total_seconds() > 300:  # 5 min gap
                    # Flush current session
                    sessions.append(_build_session(session_id, source, current_session))
                    session_id += 1
                    current_session = []
            
            current_session.append({**a, "_ts": ts})
        
        if current_session:
            sessions.append(_build_session(session_id, source, current_session))
            session_id += 1
    
    sessions.sort(key=lambda s: s["risk_score"], reverse=True)
    return sessions[:30]


def _build_session(sid, source, events):
    """Build a session summary from grouped events."""
    severities = [e.get("severity", "LOW") for e in events]
    destinations = list({e.get("target", "unknown") for e in events})
    protocols = list({e.get("protocol", "unknown") for e in events})
    
    # Risk = sum of weighted severities
    risk = sum(3 if s == "HIGH" else 2 if s == "MEDIUM" else 1 for s in severities)
    
    # Determine session label
    if any("Shadow AI" in e.get("description", "") for e in events):
        label = "Shadow AI Activity"
    elif any("anomalous" in e.get("description", "").lower() for e in events):
        label = "Anomalous Traffic"
    else:
        label = "Network Activity"
    
    timeline = []
    for e in events:
        timeline.append({
            "timestamp": e.get("timestamp"),
            "description": e.get("description", ""),
            "severity": e.get("severity", "LOW"),
            "target": e.get("target", "unknown"),
        })
    
    return {
        "id": f"session-{sid}",
        "source": source,
        "label": label,
        "alert_count": len(events),
        "risk_score": risk,
        "max_severity": "HIGH" if "HIGH" in severities else "MEDIUM" if "MEDIUM" in severities else "LOW",
        "start_time": events[0].get("timestamp"),
        "end_time": events[-1].get("timestamp"),
        "duration_seconds": int((events[-1]["_ts"] - events[0]["_ts"]).total_seconds()),
        "destinations": destinations,
        "protocols": protocols,
        "timeline": timeline,
        "severity_breakdown": {
            "HIGH": severities.count("HIGH"),
            "MEDIUM": severities.count("MEDIUM"),
            "LOW": severities.count("LOW"),
        },
    }

@router.get("/profiles")
async def get_profiles():
    """
    Build per-user (source IP) behavioral profiles from alert history.
    Tracks hour distribution, frequent destinations, severity trend, and anomalies.
    """
    from collections import Counter, defaultdict
    from datetime import datetime

    alerts = _alerts_store
    profiles = defaultdict(lambda: {
        "hours": Counter(),
        "destinations": Counter(),
        "protocols": Counter(),
        "severities": Counter(),
        "alert_count": 0,
        "first_seen": None,
        "last_seen": None,
        "alerts": [],
    })

    for a in alerts:
        src = a.get("source", "unknown")
        p = profiles[src]
        p["alert_count"] += 1
        p["severities"][a.get("severity", "LOW")] += 1
        p["destinations"][a.get("target", "unknown")] += 1
        p["protocols"][a.get("protocol", "unknown")] += 1

        ts = a.get("timestamp", "")
        try:
            dt = datetime.fromisoformat(ts)
            hour = dt.hour
            p["hours"][hour] += 1
            if p["first_seen"] is None or dt.isoformat() < p["first_seen"]:
                p["first_seen"] = dt.isoformat()
            if p["last_seen"] is None or dt.isoformat() > p["last_seen"]:
                p["last_seen"] = dt.isoformat()
        except Exception:
            pass

        p["alerts"].append(a)

    # Build response
    result = []
    for ip, prof in profiles.items():
        # Determine typical hours (hours with >25% of alerts)
        total_h = sum(prof["hours"].values()) or 1
        typical_hours = [h for h, c in prof["hours"].items() if (c / total_h) > 0.15]

        # Detect anomalies
        anomalies = []
        # Unusual hours: alerts outside typical business hours (8-18)
        off_hours = sum(c for h, c in prof["hours"].items() if h < 8 or h > 18)
        if off_hours > 0 and (off_hours / total_h) > 0.3:
            anomalies.append({"type": "unusual_hours", "detail": f"{off_hours} alerts outside business hours"})

        # High concentration on single destination
        if prof["destinations"]:
            top_dst, top_count = prof["destinations"].most_common(1)[0]
            if top_count > 3 and (top_count / prof["alert_count"]) > 0.6:
                anomalies.append({"type": "single_target_focus", "detail": f"{top_count} alerts targeting {top_dst}"})

        # High severity ratio
        high_count = prof["severities"].get("HIGH", 0)
        if high_count > 2 and (high_count / prof["alert_count"]) > 0.5:
            anomalies.append({"type": "high_severity_ratio", "detail": f"{high_count}/{prof['alert_count']} alerts are HIGH severity"})

        # Risk score: weighted
        risk = (prof["severities"].get("HIGH", 0) * 3 +
                prof["severities"].get("MEDIUM", 0) * 2 +
                prof["severities"].get("LOW", 0) * 1)

        result.append({
            "ip": ip,
            "alert_count": prof["alert_count"],
            "risk_score": risk,
            "first_seen": prof["first_seen"],
            "last_seen": prof["last_seen"],
            "typical_hours": sorted(typical_hours),
            "top_destinations": [{"target": t, "count": c} for t, c in prof["destinations"].most_common(5)],
            "protocols": dict(prof["protocols"]),
            "severity_breakdown": dict(prof["severities"]),
            "anomalies": anomalies,
            "hour_distribution": {str(h): c for h, c in sorted(prof["hours"].items())},
        })

    result.sort(key=lambda x: x["risk_score"], reverse=True)
    return result[:20]

@router.get("/report")
async def generate_report():
    """
    Generate a Shadow AI usage report from current alert data.
    Returns a JSON summary suitable for display or export.
    """
    from collections import Counter
    from datetime import datetime
    
    alerts = _alerts_store
    total = len(alerts)
    
    # Severity breakdown
    sev_counts = Counter(a.get("severity", "LOW") for a in alerts)
    
    # Unique source IPs
    sources = Counter(a.get("source", "unknown") for a in alerts)
    
    # Unique destinations
    targets = Counter(a.get("target", "unknown") for a in alerts)
    
    # Shadow AI specific (from descriptions containing known patterns)
    shadow_alerts = [a for a in alerts if "Shadow AI" in a.get("description", "") or "shadow_ai" in str(a.get("ml_metadata", {}))]
    
    # Top offending IPs
    top_sources = sources.most_common(10)
    top_targets = targets.most_common(10)
    
    return {
        "generated_at": datetime.now().isoformat(),
        "summary": {
            "total_alerts": total,
            "shadow_ai_alerts": len(shadow_alerts),
            "unique_sources": len(sources),
            "unique_targets": len(targets),
        },
        "severity_breakdown": {
            "HIGH": sev_counts.get("HIGH", 0),
            "MEDIUM": sev_counts.get("MEDIUM", 0),
            "LOW": sev_counts.get("LOW", 0),
        },
        "top_sources": [{"ip": ip, "alert_count": c} for ip, c in top_sources],
        "top_targets": [{"ip": ip, "alert_count": c} for ip, c in top_targets],
        "shadow_ai_details": shadow_alerts[:20],
        "recommendations": [
            "Review high-severity alerts for unauthorized AI service usage",
            "Update firewall rules to block or monitor flagged AI domains",
            "Investigate top offender IPs for policy compliance",
            "Consider implementing endpoint DLP for AI data exfiltration prevention",
        ],
    }
