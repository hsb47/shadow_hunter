import React, { useState, useEffect } from "react";
import { fetchKillchain } from "./api";
import {
  Search,
  KeyRound,
  Cpu,
  Upload,
  Flame,
  ChevronRight,
  Activity,
} from "lucide-react";

const STAGE_CONFIG = [
  {
    id: "reconnaissance",
    icon: <Search size={18} />,
    color: "#3b82f6",
    gradient: "from-blue-500/20 to-blue-600/5",
    ring: "ring-blue-500/40",
  },
  {
    id: "initial_access",
    icon: <KeyRound size={18} />,
    color: "#8b5cf6",
    gradient: "from-violet-500/20 to-violet-600/5",
    ring: "ring-violet-500/40",
  },
  {
    id: "execution",
    icon: <Cpu size={18} />,
    color: "#f59e0b",
    gradient: "from-amber-500/20 to-amber-600/5",
    ring: "ring-amber-500/40",
  },
  {
    id: "exfiltration",
    icon: <Upload size={18} />,
    color: "#ef4444",
    gradient: "from-red-500/20 to-red-600/5",
    ring: "ring-red-500/40",
  },
  {
    id: "impact",
    icon: <Flame size={18} />,
    color: "#dc2626",
    gradient: "from-rose-500/20 to-rose-600/5",
    ring: "ring-rose-500/40",
  },
];

const SEV_DOT = {
  HIGH: "bg-red-500",
  MEDIUM: "bg-amber-500",
  LOW: "bg-blue-500",
};

const KillChain = () => {
  const [data, setData] = useState({
    stages: [],
    total_alerts: 0,
    active_stages: 0,
    chain_completion: 0,
  });
  const [expandedStage, setExpandedStage] = useState(null);

  useEffect(() => {
    const load = async () => {
      const result = await fetchKillchain();
      if (result) setData(result);
    };
    load();
    const interval = setInterval(load, 8000);
    return () => clearInterval(interval);
  }, []);

  const { stages, chain_completion, active_stages, total_alerts } = data;

  // Determine threat level
  const threatLevel =
    chain_completion >= 80
      ? {
          label: "CRITICAL",
          color: "text-red-400",
          bg: "bg-red-500/10",
          border: "border-red-500/30",
        }
      : chain_completion >= 60
        ? {
            label: "HIGH",
            color: "text-orange-400",
            bg: "bg-orange-500/10",
            border: "border-orange-500/30",
          }
        : chain_completion >= 40
          ? {
              label: "ELEVATED",
              color: "text-amber-400",
              bg: "bg-amber-500/10",
              border: "border-amber-500/30",
            }
          : chain_completion >= 20
            ? {
                label: "GUARDED",
                color: "text-blue-400",
                bg: "bg-blue-500/10",
                border: "border-blue-500/30",
              }
            : {
                label: "LOW",
                color: "text-emerald-400",
                bg: "bg-emerald-500/10",
                border: "border-emerald-500/30",
              };

  return (
    <div className="h-full overflow-y-auto space-y-4 custom-scrollbar">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Activity size={14} className="text-red-400" />
          <span className="text-xs font-mono font-bold text-slate-300 uppercase tracking-widest">
            Kill Chain Analysis
          </span>
        </div>
        <span
          className={`text-[9px] font-mono font-bold px-2 py-0.5 rounded-full border ${threatLevel.bg} ${threatLevel.color} ${threatLevel.border}`}
        >
          THREAT: {threatLevel.label}
        </span>
      </div>

      {/* Chain Completion Progress */}
      <div className="bg-sh-panel border border-sh-border rounded-xl p-4">
        <div className="flex items-center justify-between mb-2">
          <span className="text-[10px] font-mono text-slate-500 uppercase tracking-widest">
            Attack Chain Progression
          </span>
          <span className="text-lg font-mono font-bold text-red-400">
            {chain_completion}%
          </span>
        </div>

        {/* Progress bar */}
        <div className="w-full h-2 bg-slate-800 rounded-full overflow-hidden mb-3">
          <div
            className="h-full rounded-full transition-all duration-1000"
            style={{
              width: `${chain_completion}%`,
              background: `linear-gradient(90deg, #3b82f6 0%, #8b5cf6 25%, #f59e0b 50%, #ef4444 75%, #dc2626 100%)`,
              boxShadow:
                chain_completion > 0
                  ? `0 0 12px rgba(239, 68, 68, ${chain_completion / 200})`
                  : "none",
            }}
          />
        </div>

        <div className="flex justify-between text-[9px] font-mono text-slate-600">
          <span>{active_stages}/5 stages active</span>
          <span>{total_alerts} total alerts classified</span>
        </div>
      </div>

      {/* ═══ KILL CHAIN PIPELINE ═══ */}
      <div className="relative">
        {/* Connecting line */}
        <div className="absolute left-0 right-0 top-[44px] h-0.5 bg-slate-800 z-0" />
        <div
          className="absolute left-0 top-[44px] h-0.5 z-10 transition-all duration-1000"
          style={{
            width: `${chain_completion}%`,
            background:
              "linear-gradient(90deg, #3b82f6, #8b5cf6, #f59e0b, #ef4444, #dc2626)",
            boxShadow: "0 0 8px rgba(239,68,68,0.3)",
          }}
        />

        {/* Stages */}
        <div className="grid grid-cols-5 gap-2 relative z-20">
          {stages.map((stage, idx) => {
            const cfg = STAGE_CONFIG[idx] || STAGE_CONFIG[0];
            const isExpanded = expandedStage === stage.id;

            return (
              <div
                key={stage.id}
                className="flex flex-col items-center cursor-pointer group"
                onClick={() => setExpandedStage(isExpanded ? null : stage.id)}
              >
                {/* Stage Node */}
                <div
                  className={`w-11 h-11 rounded-full flex items-center justify-center border-2 transition-all duration-300 ${
                    stage.active
                      ? `bg-linear-to-br ${cfg.gradient} border-current ring-2 ${cfg.ring} shadow-lg`
                      : "bg-slate-900 border-slate-700 opacity-50"
                  }`}
                  style={{ color: stage.active ? cfg.color : "#475569" }}
                >
                  {cfg.icon}
                </div>

                {/* Count Badge */}
                {stage.count > 0 && (
                  <div
                    className="absolute -top-1 right-[calc(50%-8px)] w-4 h-4 rounded-full text-[8px] font-bold flex items-center justify-center text-white"
                    style={{ backgroundColor: cfg.color }}
                  >
                    {stage.count > 9 ? "9+" : stage.count}
                  </div>
                )}

                {/* Label */}
                <span
                  className={`text-[8px] font-mono font-bold mt-2 text-center leading-tight transition-colors ${
                    stage.active ? "text-slate-300" : "text-slate-600"
                  } group-hover:text-slate-200`}
                >
                  {stage.label}
                </span>
              </div>
            );
          })}
        </div>
      </div>

      {/* ═══ STAGE DETAILS ═══ */}
      {stages.map((stage, idx) => {
        const cfg = STAGE_CONFIG[idx] || STAGE_CONFIG[0];
        if (expandedStage !== stage.id) return null;

        return (
          <div
            key={stage.id}
            className="bg-sh-panel border rounded-xl overflow-hidden transition-all"
            style={{ borderColor: `${cfg.color}40` }}
          >
            {/* Stage Header */}
            <div
              className="p-3 flex items-center gap-3"
              style={{ borderBottom: `1px solid ${cfg.color}20` }}
            >
              <div
                className="w-8 h-8 rounded-lg flex items-center justify-center"
                style={{ backgroundColor: `${cfg.color}15`, color: cfg.color }}
              >
                {cfg.icon}
              </div>
              <div className="flex-1">
                <div className="text-xs font-mono font-bold text-slate-200">
                  {stage.label}
                </div>
                <div className="text-[10px] text-slate-500">
                  {stage.description}
                </div>
              </div>
              <span
                className="text-lg font-mono font-bold"
                style={{ color: cfg.color }}
              >
                {stage.count}
              </span>
            </div>

            {/* Alert List */}
            {stage.alerts.length > 0 ? (
              <div className="p-2 space-y-1">
                {stage.alerts.map((alert, aIdx) => (
                  <div
                    key={aIdx}
                    className="flex items-center gap-2 px-2 py-1.5 bg-slate-950/50 rounded text-[10px] font-mono hover:bg-slate-900/50 transition-colors"
                  >
                    <div
                      className={`w-1.5 h-1.5 rounded-full flex-none ${SEV_DOT[alert.severity] || SEV_DOT.LOW}`}
                    />
                    <span className="text-slate-400 truncate flex-1">
                      {alert.description || "Unknown event"}
                    </span>
                    <span className="text-slate-600 flex-none">
                      {alert.source}
                    </span>
                  </div>
                ))}
              </div>
            ) : (
              <div className="p-4 text-center text-[10px] font-mono text-slate-600">
                No alerts in this stage
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
};

export default KillChain;
