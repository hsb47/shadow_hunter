import React, { useState, useEffect } from "react";
import { fetchDlpIncidents } from "./api";
import {
  ShieldAlert,
  KeyRound,
  FileCode,
  FileText,
  Upload,
  AlertTriangle,
  ArrowRight,
  Database,
} from "lucide-react";

const TYPE_STYLES = {
  pii_exposure: {
    icon: <ShieldAlert size={14} />,
    color: "text-red-400",
    bg: "bg-red-500/10",
    border: "border-red-500/30",
    label: "PII Exposure",
  },
  api_key_leak: {
    icon: <KeyRound size={14} />,
    color: "text-rose-400",
    bg: "bg-rose-500/10",
    border: "border-rose-500/30",
    label: "API Key Leak",
  },
  data_exfiltration: {
    icon: <Upload size={14} />,
    color: "text-orange-400",
    bg: "bg-orange-500/10",
    border: "border-orange-500/30",
    label: "Data Exfiltration",
  },
  code_snippet: {
    icon: <FileCode size={14} />,
    color: "text-amber-400",
    bg: "bg-amber-500/10",
    border: "border-amber-500/30",
    label: "Code Upload",
  },
  document_upload: {
    icon: <FileText size={14} />,
    color: "text-yellow-400",
    bg: "bg-yellow-500/10",
    border: "border-yellow-500/30",
    label: "Document Upload",
  },
};

const SEV_BADGE = {
  HIGH: "bg-red-950/50 text-red-400 border-red-500/30",
  MEDIUM: "bg-amber-950/50 text-amber-400 border-amber-500/30",
  LOW: "bg-blue-950/50 text-blue-400 border-blue-500/30",
};

const formatBytes = (b) => {
  if (!b) return "0 B";
  if (b < 1024) return `${b} B`;
  if (b < 1048576) return `${(b / 1024).toFixed(1)} KB`;
  return `${(b / 1048576).toFixed(1)} MB`;
};

const DlpMonitor = ({ searchQuery }) => {
  const [data, setData] = useState({
    incidents: [],
    summary: { total_incidents: 0, high_severity: 0, types: {} },
  });

  useEffect(() => {
    const load = async () => {
      const result = await fetchDlpIncidents();
      if (result) setData(result);
    };
    load();
    const interval = setInterval(load, 8000);
    return () => clearInterval(interval);
  }, []);

  const filtered = data.incidents.filter((inc) => {
    if (!searchQuery) return true;
    const q = searchQuery.toLowerCase();
    return (
      inc.source.toLowerCase().includes(q) ||
      inc.target.toLowerCase().includes(q) ||
      inc.label.toLowerCase().includes(q) ||
      inc.original_alert.toLowerCase().includes(q)
    );
  });

  const { summary } = data;

  return (
    <div className="h-full overflow-y-auto space-y-3 custom-scrollbar">
      {/* Header */}
      <div className="flex items-center gap-2">
        <Database size={14} className="text-rose-400" />
        <span className="text-xs font-mono font-bold text-slate-300 uppercase tracking-widest">
          DLP Monitor
        </span>
        <span className="text-[10px] font-mono text-slate-600 bg-slate-800 px-1.5 py-0.5 rounded-full border border-slate-700">
          {summary.total_incidents} incidents
        </span>
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-3 gap-2">
        <SummaryCard
          label="Total Incidents"
          value={summary.total_incidents}
          color="text-rose-400"
        />
        <SummaryCard
          label="High Severity"
          value={summary.high_severity}
          color="text-red-400"
        />
        <SummaryCard
          label="Unique Types"
          value={Object.keys(summary.types).length}
          color="text-amber-400"
        />
      </div>

      {/* Type Breakdown */}
      {Object.keys(summary.types).length > 0 && (
        <div className="bg-sh-panel border border-sh-border rounded-xl p-3">
          <div className="text-[9px] font-mono font-bold text-slate-500 uppercase tracking-widest mb-2">
            Threat Types Detected
          </div>
          <div className="flex flex-wrap gap-2">
            {Object.entries(summary.types).map(([type, count]) => {
              const style = TYPE_STYLES[type] || TYPE_STYLES.data_exfiltration;
              return (
                <div
                  key={type}
                  className={`flex items-center gap-1.5 px-2 py-1 rounded-lg ${style.bg} border ${style.border}`}
                >
                  <span className={style.color}>{style.icon}</span>
                  <span
                    className={`text-[10px] font-mono font-bold ${style.color}`}
                  >
                    {count}
                  </span>
                  <span className="text-[9px] font-mono text-slate-500">
                    {style.label}
                  </span>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Incidents List */}
      {filtered.length === 0 ? (
        <div className="h-48 flex flex-col items-center justify-center text-slate-600">
          <Database className="w-12 h-12 mb-2 stroke-1" />
          <span className="text-xs font-mono uppercase tracking-widest">
            {searchQuery
              ? "No matching incidents"
              : "No DLP incidents detected"}
          </span>
          <span className="text-[10px] font-mono text-slate-700 mt-1">
            Data loss prevention monitoring active
          </span>
        </div>
      ) : (
        <div className="space-y-2">
          {filtered.map((inc) => {
            const typeStyle =
              TYPE_STYLES[inc.type] || TYPE_STYLES.data_exfiltration;
            return (
              <div
                key={inc.id}
                className="bg-sh-panel border border-sh-border rounded-xl p-3 hover:border-slate-600 transition-all"
              >
                <div className="flex items-start gap-3">
                  {/* Type Icon */}
                  <div
                    className={`w-8 h-8 rounded-lg flex items-center justify-center ${typeStyle.bg} border ${typeStyle.border} flex-none`}
                  >
                    <span className={typeStyle.color}>{typeStyle.icon}</span>
                  </div>

                  <div className="flex-1 min-w-0">
                    {/* Title row */}
                    <div className="flex items-center gap-2 mb-1">
                      <span className="text-xs font-mono font-bold text-slate-200">
                        {inc.label}
                      </span>
                      <span
                        className={`text-[9px] font-bold px-1 py-px rounded border ${SEV_BADGE[inc.severity]}`}
                      >
                        {inc.severity}
                      </span>
                    </div>

                    {/* Description */}
                    <p className="text-[10px] text-slate-500 mb-1.5">
                      {inc.description}
                    </p>

                    {/* Source → Target */}
                    <div className="flex items-center gap-2 text-[10px] font-mono bg-slate-950/50 p-1.5 rounded border border-slate-800/50 mb-1.5">
                      <span className="text-blue-400">{inc.source}</span>
                      <ArrowRight size={10} className="text-slate-600" />
                      <span className="text-red-400 truncate">
                        {inc.target}
                      </span>
                      {inc.bytes_sent > 0 && (
                        <>
                          <span className="text-slate-700">•</span>
                          <span className="text-slate-500">
                            {formatBytes(inc.bytes_sent)}
                          </span>
                        </>
                      )}
                    </div>

                    {/* Original Alert + Timestamp */}
                    <div className="flex items-center justify-between">
                      <span className="text-[9px] text-slate-600 truncate max-w-[60%]">
                        {inc.original_alert}
                      </span>
                      <span className="text-[9px] font-mono text-slate-600">
                        {inc.timestamp
                          ? new Date(inc.timestamp).toLocaleTimeString([], {
                              hour12: false,
                            })
                          : "—"}
                      </span>
                    </div>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
};

const SummaryCard = ({ label, value, color }) => (
  <div className="bg-sh-panel border border-sh-border rounded-lg p-2.5 text-center">
    <div className={`text-lg font-mono font-bold ${color}`}>{value}</div>
    <div className="text-[8px] font-mono text-slate-500 uppercase tracking-wider">
      {label}
    </div>
  </div>
);

export default DlpMonitor;
