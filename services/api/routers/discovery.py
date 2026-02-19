from fastapi import APIRouter, Depends
from typing import List, Dict, Any
from collections import Counter
from services.api.dependencies import get_graph_store
from services.api.routers.policy import get_alerts_store
from pkg.core.interfaces import GraphStore

router = APIRouter()

@router.get("/nodes")
async def get_nodes(store: GraphStore = Depends(get_graph_store)):
    """
    Retrieve all discovered nodes from the GraphStore.
    """
    nodes = await store.get_all_nodes()
    return nodes

@router.get("/edges")
async def get_edges(store: GraphStore = Depends(get_graph_store)):
    """
    Retrieve all discovered dependencies from the GraphStore.
    """
    edges = await store.get_all_edges()
    return edges

@router.get("/risk-scores")
async def get_risk_scores(store: GraphStore = Depends(get_graph_store)):
    """
    Calculate risk scores per internal IP based on alert frequency and severity.
    Returns sorted list: highest risk first.
    """
    alerts = get_alerts_store()
    
    # Count alerts per source IP with severity weighting
    SEVERITY_WEIGHTS = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}
    ip_scores: Dict[str, dict] = {}
    
    for alert in alerts:
        src = alert.get("source", "unknown")
        sev = alert.get("severity", "LOW")
        weight = SEVERITY_WEIGHTS.get(sev, 1)
        
        if src not in ip_scores:
            ip_scores[src] = {"ip": src, "total_alerts": 0, "weighted_score": 0, "high": 0, "medium": 0, "low": 0, "last_alert": ""}
        
        ip_scores[src]["total_alerts"] += 1
        ip_scores[src]["weighted_score"] += weight
        ip_scores[src][sev.lower()] = ip_scores[src].get(sev.lower(), 0) + 1
        ip_scores[src]["last_alert"] = alert.get("timestamp", "")
    
    # Normalize scores to 0-100
    if ip_scores:
        max_score = max(v["weighted_score"] for v in ip_scores.values()) or 1
        for v in ip_scores.values():
            v["risk_pct"] = round((v["weighted_score"] / max_score) * 100)
    
    # Sort by weighted score descending
    result = sorted(ip_scores.values(), key=lambda x: x["weighted_score"], reverse=True)
    return result[:20]  # Top 20 offenders

@router.get("/traffic-stats")
async def get_traffic_stats(store: GraphStore = Depends(get_graph_store)):
    """
    Traffic statistics for dashboard visualization.
    Returns protocol breakdown, traffic classification, and time-series data.
    """
    from collections import Counter, defaultdict
    from datetime import datetime
    
    edges = await store.get_all_edges()
    nodes = await store.get_all_nodes()
    alerts = get_alerts_store()
    
    # Protocol distribution
    protocol_counts = Counter(e.get("protocol", "unknown") for e in edges)
    
    # Node type distribution  
    type_counts = Counter(n.get("type", "unknown") for n in nodes)
    
    # Traffic classification from alerts
    total_events = len(edges)
    shadow_count = type_counts.get("shadow", 0)
    
    # Alert severity distribution
    severity_counts = Counter(a.get("severity", "LOW") for a in alerts)
    
    # Bytes distribution (top destinations by traffic volume)
    dst_bytes = defaultdict(int)
    for e in edges:
        target = e.get("target", "unknown")
        byte_count = e.get("byte_count", 0)
        dst_bytes[target] += byte_count
    top_destinations = sorted(dst_bytes.items(), key=lambda x: x[1], reverse=True)[:10]
    
    # Traffic comparison: AI vs Normal
    ai_traffic_count = sum(1 for n in nodes if n.get("type") == "shadow")
    normal_traffic_count = sum(1 for n in nodes if n.get("type") == "external")
    internal_count = sum(1 for n in nodes if n.get("type") == "internal")
    
    return {
        "protocol_distribution": [
            {"name": proto, "value": count}
            for proto, count in protocol_counts.most_common()
        ],
        "node_types": {
            "internal": internal_count,
            "external": normal_traffic_count,
            "shadow_ai": ai_traffic_count,
        },
        "severity_distribution": {
            "HIGH": severity_counts.get("HIGH", 0),
            "MEDIUM": severity_counts.get("MEDIUM", 0),
            "LOW": severity_counts.get("LOW", 0),
        },
        "top_destinations": [
            {"destination": dst, "bytes": bts}
            for dst, bts in top_destinations
        ],
        "totals": {
            "total_nodes": len(nodes),
            "total_connections": len(edges),
            "total_alerts": len(alerts),
        }
    }

