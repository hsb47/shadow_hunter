import React, { useEffect, useState } from "react";
import { fetchAlerts } from "./api";
import {
  AlertTriangle,
  ShieldAlert,
  XCircle,
  ArrowRight,
  Download,
  X,
  Clock,
  Cpu,
  Network,
  Activity,
  Shield,
  ChevronRight,
  Crosshair,
  Zap,
  ExternalLink,
} from "lucide-react";

const Alerts = ({ searchQuery, onExport, onNavigateToNode }) => {
  const [alerts, setAlerts] = useState([]);
  const [selectedAlert, setSelectedAlert] = useState(null);

  useEffect(() => {
    const loadAlerts = async () => {
      const data = await fetchAlerts();
      setAlerts(data);
    };

    loadAlerts();
    const interval = setInterval(loadAlerts, 5000);
    return () => clearInterval(interval);
  }, []);

  const filtered = alerts.filter((a) => {
    if (!searchQuery) return true;
    const q = searchQuery.toLowerCase();
    return (
      a.description?.toLowerCase().includes(q) ||
      a.source?.toLowerCase().includes(q) ||
      a.target?.toLowerCase().includes(q)
    );
  });

  const severityConfig = {
    HIGH: {
      stripe: "bg-red-500 shadow-[0_0_10px_#ef4444]",
      badge: "bg-red-950/50 text-red-500 border-red-500/30",
      glow: "shadow-[0_0_20px_rgba(239,68,68,0.15)]",
      dot: "bg-red-500",
    },
    MEDIUM: {
      stripe: "bg-amber-500",
      badge: "bg-amber-950/50 text-amber-500 border-amber-500/30",
      glow: "shadow-[0_0_20px_rgba(245,158,11,0.15)]",
      dot: "bg-amber-500",
    },
    LOW: {
      stripe: "bg-blue-500",
      badge: "bg-blue-950/50 text-blue-400 border-blue-500/30",
      glow: "shadow-[0_0_20px_rgba(59,130,246,0.15)]",
      dot: "bg-blue-500",
    },
  };

  // Find related alerts for the selected alert
  const relatedAlerts = selectedAlert
    ? filtered.filter(
        (a) =>
          a.id !== selectedAlert.id &&
          (a.source === selectedAlert.source ||
            a.target === selectedAlert.target),
      )
    : [];

  return (
    <div className="h-full flex flex-col bg-sh-panel rounded-2xl border border-sh-border shadow-xl overflow-hidden relative">
      {/* Header */}
      <div className="p-4 border-b border-sh-border bg-slate-900/50 backdrop-blur flex justify-between items-center flex-none">
        <div className="flex items-center gap-2">
          <ShieldAlert className="w-4 h-4 text-red-400 animate-pulse" />
          <span className="font-bold text-sm tracking-wider text-slate-200 uppercase">
            Intel Feed
          </span>
        </div>
        <div className="flex items-center gap-3">
          {onExport && (
            <button
              onClick={() => onExport(filtered)}
              className="flex items-center gap-1.5 text-[10px] font-mono font-bold text-slate-400 hover:text-white transition-colors bg-slate-800 hover:bg-slate-700 px-2 py-1 rounded border border-slate-700 hover:border-slate-500"
            >
              <Download size={10} />
              CSV
            </button>
          )}
          <span className="text-[10px] font-mono text-slate-500 bg-slate-800 px-2 py-0.5 rounded-full border border-slate-700">
            LIVE
          </span>
        </div>
      </div>

      {/* List */}
      <div className="flex-1 overflow-y-auto p-2 space-y-2 custom-scrollbar">
        {filtered.length === 0 ? (
          <div className="h-full flex flex-col items-center justify-center text-slate-600 opacity-50">
            <ShieldAlert className="w-12 h-12 mb-2 stroke-1" />
            <span className="text-xs font-mono uppercase tracking-widest">
              {searchQuery ? "No matches found" : "System Secure"}
            </span>
          </div>
        ) : (
          filtered.map((alert) => {
            const sev = severityConfig[alert.severity] || severityConfig.LOW;
            const isSelected = selectedAlert?.id === alert.id;

            return (
              <div
                key={alert.id}
                onClick={() => setSelectedAlert(isSelected ? null : alert)}
                className={`group relative bg-slate-900/80 hover:bg-slate-800 p-3 rounded-lg border transition-all cursor-pointer ${
                  isSelected
                    ? `border-slate-500 ${sev.glow}`
                    : "border-sh-border hover:border-slate-600"
                }`}
              >
                {/* Severity Stripe */}
                <div
                  className={`absolute left-0 top-0 bottom-0 w-1 rounded-l-lg ${sev.stripe}`}
                ></div>

                <div className="pl-3">
                  <div className="flex justify-between items-start mb-1">
                    <span
                      className={`text-[10px] font-bold px-1.5 py-0.5 rounded border ${sev.badge}`}
                    >
                      {alert.severity}
                    </span>
                    <div className="flex items-center gap-2">
                      <span className="text-[10px] font-mono text-slate-500">
                        {new Date(alert.timestamp).toLocaleTimeString([], {
                          hour12: false,
                        })}
                      </span>
                      <ChevronRight
                        size={12}
                        className={`text-slate-600 transition-transform ${isSelected ? "rotate-90" : "group-hover:translate-x-0.5"}`}
                      />
                    </div>
                  </div>

                  <div className="text-xs text-slate-300 font-medium leading-relaxed mb-2">
                    {alert.description}
                  </div>

                  {alert.source && (
                    <div className="flex items-center gap-2 text-[10px] font-mono text-slate-500 bg-slate-950/50 p-1.5 rounded border border-slate-800/50">
                      <span className="text-blue-400">{alert.source}</span>
                      <ArrowRight className="w-3 h-3 text-slate-600" />
                      <span className="text-red-400">{alert.target}</span>
                    </div>
                  )}
                </div>

                {/* ═══ Expanded Drill-Down Panel ═══ */}
                {isSelected && (
                  <div className="mt-3 pt-3 border-t border-sh-border/50 pl-3 space-y-3 animate-in fade-in slide-in-from-top-2 duration-200">
                    {/* Packet Metadata */}
                    <DetailSection
                      icon={<Network size={11} />}
                      title="Packet Metadata"
                    >
                      <div className="grid grid-cols-2 gap-1.5">
                        <MetaField
                          label="Protocol"
                          value={alert.protocol || "—"}
                        />
                        <MetaField
                          label="Dst Port"
                          value={alert.destination_port || "—"}
                        />
                        <MetaField
                          label="Src Port"
                          value={alert.source_port || "—"}
                        />
                        <MetaField
                          label="Dst IP"
                          value={alert.destination_ip || "—"}
                        />
                        <MetaField
                          label="Bytes Sent"
                          value={
                            alert.bytes_sent != null
                              ? formatBytes(alert.bytes_sent)
                              : "—"
                          }
                        />
                        <MetaField
                          label="Bytes Recv"
                          value={
                            alert.bytes_received != null
                              ? formatBytes(alert.bytes_received)
                              : "—"
                          }
                        />
                      </div>
                    </DetailSection>

                    {/* Matched Rule */}
                    <DetailSection
                      icon={<Crosshair size={11} />}
                      title="Detection"
                    >
                      <div className="text-[11px] font-mono text-slate-300 bg-slate-950/50 p-2 rounded border border-sh-border/30 leading-relaxed">
                        {alert.matched_rule || alert.description}
                      </div>
                    </DetailSection>

                    {/* ML Intelligence (conditional) */}
                    {alert.ml_classification && (
                      <DetailSection
                        icon={<Cpu size={11} />}
                        title="ML Intelligence"
                      >
                        <div className="space-y-2">
                          <div className="flex items-center justify-between">
                            <span className="text-[10px] font-mono text-slate-500">
                              Classification
                            </span>
                            <span
                              className={`text-[10px] font-mono font-bold px-1.5 py-0.5 rounded border ${
                                alert.ml_classification === "shadow_ai"
                                  ? "bg-red-500/10 text-red-400 border-red-500/30"
                                  : alert.ml_classification === "suspicious"
                                    ? "bg-amber-500/10 text-amber-400 border-amber-500/30"
                                    : "bg-blue-500/10 text-blue-400 border-blue-500/30"
                              }`}
                            >
                              {alert.ml_classification
                                .replace("_", " ")
                                .toUpperCase()}
                            </span>
                          </div>

                          {/* Confidence Bar */}
                          {alert.ml_confidence != null && (
                            <div>
                              <div className="flex items-center justify-between mb-1">
                                <span className="text-[10px] font-mono text-slate-500">
                                  Confidence
                                </span>
                                <span className="text-[10px] font-mono font-bold text-slate-300">
                                  {(alert.ml_confidence * 100).toFixed(0)}%
                                </span>
                              </div>
                              <div className="w-full bg-slate-800 rounded-full h-1.5">
                                <div
                                  className={`h-1.5 rounded-full transition-all duration-500 ${
                                    alert.ml_confidence > 0.7
                                      ? "bg-red-500"
                                      : alert.ml_confidence > 0.4
                                        ? "bg-amber-500"
                                        : "bg-blue-500"
                                  }`}
                                  style={{
                                    width: `${(alert.ml_confidence * 100).toFixed(0)}%`,
                                  }}
                                />
                              </div>
                            </div>
                          )}

                          {alert.ml_risk_score != null && (
                            <div className="flex items-center justify-between">
                              <span className="text-[10px] font-mono text-slate-500">
                                Risk Score
                              </span>
                              <span
                                className={`text-[10px] font-mono font-bold ${
                                  alert.ml_risk_score > 70
                                    ? "text-red-400"
                                    : alert.ml_risk_score > 40
                                      ? "text-amber-400"
                                      : "text-blue-400"
                                }`}
                              >
                                {typeof alert.ml_risk_score === "number"
                                  ? alert.ml_risk_score.toFixed(1)
                                  : alert.ml_risk_score}
                              </span>
                            </div>
                          )}
                        </div>
                      </DetailSection>
                    )}

                    {/* Timestamp Details */}
                    <DetailSection icon={<Clock size={11} />} title="Timestamp">
                      <div className="text-[11px] font-mono text-slate-400">
                        {new Date(alert.timestamp).toLocaleString([], {
                          year: "numeric",
                          month: "short",
                          day: "numeric",
                          hour: "2-digit",
                          minute: "2-digit",
                          second: "2-digit",
                          hour12: false,
                        })}
                      </div>
                      <div className="text-[9px] font-mono text-slate-600 mt-0.5">
                        ID: {alert.id}
                      </div>
                    </DetailSection>

                    {/* Source / Target Navigation */}
                    {onNavigateToNode && (
                      <DetailSection
                        icon={<ExternalLink size={11} />}
                        title="Navigate to Node"
                      >
                        <div className="flex gap-2">
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              onNavigateToNode(alert.source);
                            }}
                            className="flex-1 flex items-center justify-center gap-1.5 text-[10px] font-mono font-bold text-blue-400 bg-blue-500/10 hover:bg-blue-500/20 border border-blue-500/30 rounded-lg py-1.5 px-2 transition-all"
                          >
                            <Zap size={10} />
                            Source
                          </button>
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              onNavigateToNode(alert.target);
                            }}
                            className="flex-1 flex items-center justify-center gap-1.5 text-[10px] font-mono font-bold text-red-400 bg-red-500/10 hover:bg-red-500/20 border border-red-500/30 rounded-lg py-1.5 px-2 transition-all"
                          >
                            <Crosshair size={10} />
                            Target
                          </button>
                        </div>
                      </DetailSection>
                    )}

                    {/* Related Events */}
                    {relatedAlerts.length > 0 && (
                      <DetailSection
                        icon={<Activity size={11} />}
                        title={`Related Events (${relatedAlerts.length})`}
                      >
                        <div className="space-y-1 max-h-24 overflow-y-auto custom-scrollbar">
                          {relatedAlerts.slice(0, 5).map((ra) => (
                            <div
                              key={ra.id}
                              onClick={(e) => {
                                e.stopPropagation();
                                setSelectedAlert(ra);
                              }}
                              className="flex items-center gap-2 text-[10px] font-mono text-slate-400 bg-slate-950/50 border border-sh-border/30 rounded px-2 py-1 hover:bg-slate-800/50 cursor-pointer transition-colors"
                            >
                              <span
                                className={`w-1.5 h-1.5 rounded-full flex-none ${severityConfig[ra.severity]?.dot || "bg-slate-500"}`}
                              />
                              <span className="truncate flex-1">
                                {ra.description}
                              </span>
                              <span className="text-slate-600 flex-none">
                                {new Date(ra.timestamp).toLocaleTimeString([], {
                                  hour12: false,
                                })}
                              </span>
                            </div>
                          ))}
                        </div>
                      </DetailSection>
                    )}
                  </div>
                )}
              </div>
            );
          })
        )}
      </div>
    </div>
  );
};

// ═══════════════════════════════════════════════════════
// Sub-components
// ═══════════════════════════════════════════════════════

const DetailSection = ({ icon, title, children }) => (
  <div>
    <div className="flex items-center gap-1.5 mb-1.5">
      <span className="text-slate-500">{icon}</span>
      <span className="text-[9px] font-mono font-bold text-slate-500 uppercase tracking-widest">
        {title}
      </span>
    </div>
    {children}
  </div>
);

const MetaField = ({ label, value }) => (
  <div className="bg-slate-950/50 border border-sh-border/30 rounded px-2 py-1">
    <div className="text-[8px] font-mono text-slate-600 uppercase tracking-wider">
      {label}
    </div>
    <div className="text-[11px] font-mono text-slate-300 truncate">{value}</div>
  </div>
);

const formatBytes = (bytes) => {
  if (bytes === 0) return "0 B";
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
};

export default Alerts;
