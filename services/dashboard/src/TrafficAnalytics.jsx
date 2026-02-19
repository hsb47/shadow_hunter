import React, { useState, useEffect } from "react";
import { fetchTrafficStats } from "./api";
import {
  BarChart3,
  PieChart,
  Shield,
  Wifi,
  ArrowUpRight,
  ArrowDownRight,
} from "lucide-react";

const COLORS = {
  HTTPS: "#3b82f6",
  TCP: "#06b6d4",
  UDP: "#8b5cf6",
  DNS: "#f59e0b",
  HTTP: "#10b981",
  unknown: "#64748b",
};

const SEV_COLORS = {
  HIGH: { bg: "bg-red-500", text: "text-red-400", bar: "#ef4444" },
  MEDIUM: { bg: "bg-amber-500", text: "text-amber-400", bar: "#f59e0b" },
  LOW: { bg: "bg-blue-500", text: "text-blue-400", bar: "#3b82f6" },
};

const TrafficAnalytics = () => {
  const [stats, setStats] = useState(null);

  useEffect(() => {
    const load = async () => {
      const data = await fetchTrafficStats();
      setStats(data);
    };
    load();
    const interval = setInterval(load, 5000);
    return () => clearInterval(interval);
  }, []);

  if (!stats) {
    return (
      <div className="h-full flex items-center justify-center text-slate-500 font-mono text-sm">
        Loading analytics...
      </div>
    );
  }

  const totalProtocol =
    stats.protocol_distribution.reduce((s, p) => s + p.value, 0) || 1;
  const totalSeverity =
    stats.severity_distribution.HIGH +
      stats.severity_distribution.MEDIUM +
      stats.severity_distribution.LOW || 1;
  const totalNodes =
    stats.node_types.internal +
      stats.node_types.external +
      stats.node_types.shadow_ai || 1;

  return (
    <div className="h-full overflow-y-auto p-3 space-y-3 custom-scrollbar">
      {/* Row 1: Summary Cards */}
      <div className="grid grid-cols-4 gap-3">
        <SummaryCard
          label="Total Nodes"
          value={stats.totals.total_nodes}
          icon={<Wifi size={16} />}
          color="text-blue-400"
        />
        <SummaryCard
          label="Connections"
          value={stats.totals.total_connections}
          icon={<ArrowUpRight size={16} />}
          color="text-cyan-400"
        />
        <SummaryCard
          label="Total Alerts"
          value={stats.totals.total_alerts}
          icon={<Shield size={16} />}
          color="text-amber-400"
        />
        <SummaryCard
          label="Shadow AI Nodes"
          value={stats.node_types.shadow_ai}
          icon={<ArrowDownRight size={16} />}
          color="text-red-400"
          highlight={stats.node_types.shadow_ai > 0}
        />
      </div>

      {/* Row 2: Traffic Comparison + Protocol Breakdown */}
      <div className="grid grid-cols-2 gap-3">
        {/* AI vs Normal Comparison */}
        <div className="bg-sh-panel border border-sh-border rounded-xl overflow-hidden">
          <div className="px-4 py-2.5 border-b border-sh-border bg-slate-900/50 text-[10px] font-mono font-bold text-slate-400 uppercase tracking-widest flex items-center gap-2">
            <PieChart size={12} className="text-cyan-400" />
            AI vs Normal Traffic
          </div>
          <div className="p-4 space-y-3">
            {/* Visual donut-style breakdown */}
            <div className="flex items-center gap-4">
              <div className="relative w-24 h-24 flex-none">
                <svg viewBox="0 0 100 100" className="w-full h-full -rotate-90">
                  {(() => {
                    const segments = [
                      {
                        value: stats.node_types.internal,
                        color: "#0ea5e9",
                        label: "Internal",
                      },
                      {
                        value: stats.node_types.external,
                        color: "#10b981",
                        label: "External",
                      },
                      {
                        value: stats.node_types.shadow_ai,
                        color: "#ef4444",
                        label: "Shadow AI",
                      },
                    ];
                    let offset = 0;
                    return segments.map((seg, i) => {
                      const pct = (seg.value / totalNodes) * 100;
                      const circumference = 2 * Math.PI * 35;
                      const dashLen = (pct / 100) * circumference;
                      const el = (
                        <circle
                          key={i}
                          cx="50"
                          cy="50"
                          r="35"
                          fill="none"
                          stroke={seg.color}
                          strokeWidth="12"
                          strokeDasharray={`${dashLen} ${circumference}`}
                          strokeDashoffset={-(offset / 100) * circumference}
                          className="transition-all duration-300"
                        />
                      );
                      offset += pct;
                      return el;
                    });
                  })()}
                  {/* Center circle */}
                  <circle cx="50" cy="50" r="25" fill="#0f172a" />
                </svg>
                <div className="absolute inset-0 flex items-center justify-center">
                  <span className="text-sm font-mono font-bold text-slate-300">
                    {totalNodes}
                  </span>
                </div>
              </div>
              <div className="space-y-2 flex-1">
                <LegendRow
                  color="#0ea5e9"
                  label="Internal"
                  value={stats.node_types.internal}
                  pct={((stats.node_types.internal / totalNodes) * 100).toFixed(
                    0,
                  )}
                />
                <LegendRow
                  color="#10b981"
                  label="External"
                  value={stats.node_types.external}
                  pct={((stats.node_types.external / totalNodes) * 100).toFixed(
                    0,
                  )}
                />
                <LegendRow
                  color="#ef4444"
                  label="Shadow AI"
                  value={stats.node_types.shadow_ai}
                  pct={(
                    (stats.node_types.shadow_ai / totalNodes) *
                    100
                  ).toFixed(0)}
                  highlight
                />
              </div>
            </div>
          </div>
        </div>

        {/* Protocol Distribution */}
        <div className="bg-sh-panel border border-sh-border rounded-xl overflow-hidden">
          <div className="px-4 py-2.5 border-b border-sh-border bg-slate-900/50 text-[10px] font-mono font-bold text-slate-400 uppercase tracking-widest flex items-center gap-2">
            <BarChart3 size={12} className="text-blue-400" />
            Protocol Distribution
          </div>
          <div className="p-4 space-y-2">
            {stats.protocol_distribution.map((p) => (
              <div key={p.name} className="space-y-1">
                <div className="flex justify-between text-xs font-mono">
                  <span className="text-slate-300">{p.name}</span>
                  <span className="text-slate-500">
                    {p.value}{" "}
                    <span className="text-slate-600">
                      ({((p.value / totalProtocol) * 100).toFixed(0)}%)
                    </span>
                  </span>
                </div>
                <div className="w-full bg-slate-800 rounded-full h-2">
                  <div
                    className="h-2 rounded-full transition-all duration-500"
                    style={{
                      width: `${(p.value / totalProtocol) * 100}%`,
                      backgroundColor: COLORS[p.name] || COLORS.unknown,
                    }}
                  />
                </div>
              </div>
            ))}
            {stats.protocol_distribution.length === 0 && (
              <div className="text-xs text-slate-600 font-mono">
                No protocol data yet
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Row 3: Severity Distribution + Top Destinations */}
      <div className="grid grid-cols-2 gap-3">
        {/* Severity Distribution */}
        <div className="bg-sh-panel border border-sh-border rounded-xl overflow-hidden">
          <div className="px-4 py-2.5 border-b border-sh-border bg-slate-900/50 text-[10px] font-mono font-bold text-slate-400 uppercase tracking-widest flex items-center gap-2">
            <Shield size={12} className="text-amber-400" />
            Alert Severity Breakdown
          </div>
          <div className="p-4 space-y-3">
            {["HIGH", "MEDIUM", "LOW"].map((sev) => {
              const count = stats.severity_distribution[sev];
              const pct = ((count / totalSeverity) * 100).toFixed(0);
              return (
                <div key={sev} className="space-y-1">
                  <div className="flex justify-between text-xs font-mono">
                    <span className={SEV_COLORS[sev].text}>{sev}</span>
                    <span className="text-slate-500">
                      {count} ({pct}%)
                    </span>
                  </div>
                  <div className="w-full bg-slate-800 rounded-full h-2.5">
                    <div
                      className="h-2.5 rounded-full transition-all duration-500"
                      style={{
                        width: `${pct}%`,
                        backgroundColor: SEV_COLORS[sev].bar,
                      }}
                    />
                  </div>
                </div>
              );
            })}
            {totalSeverity <= 1 && stats.totals.total_alerts === 0 && (
              <div className="text-xs text-slate-600 font-mono text-center py-2">
                No alerts detected — clean network ✓
              </div>
            )}
          </div>
        </div>

        {/* Top Destinations */}
        <div className="bg-sh-panel border border-sh-border rounded-xl overflow-hidden">
          <div className="px-4 py-2.5 border-b border-sh-border bg-slate-900/50 text-[10px] font-mono font-bold text-slate-400 uppercase tracking-widest">
            Top Destinations by Volume
          </div>
          <div className="overflow-y-auto max-h-[200px] custom-scrollbar">
            {stats.top_destinations.length === 0 ? (
              <div className="text-xs text-slate-600 font-mono text-center py-4">
                No traffic data yet
              </div>
            ) : (
              stats.top_destinations.map((d, i) => {
                const maxBytes = stats.top_destinations[0]?.bytes || 1;
                return (
                  <div
                    key={d.destination}
                    className="flex items-center gap-3 px-4 py-2 border-b border-sh-border/30 hover:bg-slate-800/30 transition-colors"
                  >
                    <span className="text-[10px] font-mono text-slate-600 w-5">
                      {i + 1}.
                    </span>
                    <div className="flex-1 min-w-0">
                      <div className="text-[11px] font-mono text-slate-300 truncate">
                        {d.destination}
                      </div>
                      <div className="w-full bg-slate-800 rounded-full h-1 mt-1">
                        <div
                          className="h-1 rounded-full bg-cyan-500/60"
                          style={{ width: `${(d.bytes / maxBytes) * 100}%` }}
                        />
                      </div>
                    </div>
                    <span className="text-[10px] font-mono text-slate-500 flex-none">
                      {d.bytes >= 1000
                        ? `${(d.bytes / 1000).toFixed(1)}KB`
                        : `${d.bytes}B`}
                    </span>
                  </div>
                );
              })
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

// Sub-components
const SummaryCard = ({ label, value, icon, color, highlight }) => (
  <div
    className={`bg-sh-panel border ${highlight ? "border-red-500/30" : "border-sh-border"} rounded-xl p-3 flex items-center gap-3 ${highlight ? "shadow-[0_0_15px_rgba(239,68,68,0.1)]" : ""}`}
  >
    <div className={color}>{icon}</div>
    <div>
      <div className="text-[10px] text-slate-500 font-bold tracking-wider uppercase">
        {label}
      </div>
      <div
        className={`text-xl font-mono font-bold ${highlight ? "text-red-400" : "text-slate-200"}`}
      >
        {value}
      </div>
    </div>
  </div>
);

const LegendRow = ({ color, label, value, pct, highlight }) => (
  <div className="flex items-center gap-2">
    <span
      className="w-2.5 h-2.5 rounded-sm inline-block"
      style={{ backgroundColor: color }}
    ></span>
    <span
      className={`text-xs font-mono flex-1 ${highlight ? "text-red-400 font-bold" : "text-slate-400"}`}
    >
      {label}
    </span>
    <span className="text-xs font-mono text-slate-500">{value}</span>
    <span className="text-[10px] font-mono text-slate-600">{pct}%</span>
  </div>
);

export default TrafficAnalytics;
