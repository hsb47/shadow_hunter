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
  ShieldAlert,
  Target,
  Zap,
} from "lucide-react";

const STAGE_CONFIG = [
  {
    id: "reconnaissance",
    label: "Reconnaissance",
    icon: <Search size={24} />,
    color: "#3b82f6", // Blue
    gradient: "from-blue-500 to-cyan-400",
    bg: "bg-blue-500/10",
    border: "border-blue-500/30",
    description: "Scanning & enumeration",
  },
  {
    id: "initial_access",
    label: "Initial Access",
    icon: <KeyRound size={24} />,
    color: "#8b5cf6", // Violet
    gradient: "from-violet-500 to-purple-400",
    bg: "bg-violet-500/10",
    border: "border-violet-500/30",
    description: "Payload delivery",
  },
  {
    id: "execution",
    label: "Execution",
    icon: <Cpu size={24} />,
    color: "#f59e0b", // Amber
    gradient: "from-amber-500 to-orange-400",
    bg: "bg-amber-500/10",
    border: "border-amber-500/30",
    description: "Code execution",
  },
  {
    id: "exfiltration",
    label: "Exfiltration",
    icon: <Upload size={24} />,
    color: "#ef4444", // Red
    gradient: "from-red-500 to-rose-400",
    bg: "bg-red-500/10",
    border: "border-red-500/30",
    description: "Data theft",
  },
  {
    id: "impact",
    label: "Impact",
    icon: <Flame size={24} />,
    color: "#dc2626", // Dark Red
    gradient: "from-rose-600 to-red-800",
    bg: "bg-rose-900/20",
    border: "border-rose-500/50",
    description: "System compromise",
  },
];

const SEV_DOT = {
  HIGH: "bg-red-500 shadow-[0_0_8px_rgba(239,68,68,0.6)]",
  MEDIUM: "bg-amber-500 shadow-[0_0_8px_rgba(245,158,11,0.6)]",
  LOW: "bg-blue-500 shadow-[0_0_8px_rgba(59,130,246,0.6)]",
};

const KillChain = () => {
  const [data, setData] = useState({
    stages: [],
    total_alerts: 0,
    active_stages: 0,
    chain_completion: 0,
  });
  const [expandedStage, setExpandedStage] = useState(null);

  // Effect 1: Data Polling (no dependencies)
  useEffect(() => {
    const load = async () => {
      try {
        const result = await fetchKillchain();
        if (result) setData(result);
      } catch (e) {
        console.error("Failed to load killchain data", e);
      }
    };
    load();
    const interval = setInterval(load, 5000);
    return () => clearInterval(interval);
  }, []);

  // Effect 2: Auto-Select Active Stage (runs when data updates)
  useEffect(() => {
    if (!expandedStage && data.stages.length > 0) {
      const active = data.stages.find((s) => s.active);
      if (active) setExpandedStage(active.id);
    }
  }, [data, expandedStage]);

  const { stages, chain_completion } = data;

  return (
    <div className="h-full flex flex-col gap-4 p-4 overflow-hidden relative">
      {/* Background Effect */}
      <div
        className="absolute inset-0 opacity-10 pointer-events-none"
        style={{
          backgroundImage:
            "radial-gradient(circle at 50% 50%, #1e293b 1px, transparent 1px)",
          backgroundSize: "24px 24px",
        }}
      />

      {/* ── HEADER ── */}
      <div className="flex items-center justify-between z-10">
        <div className="flex items-center gap-3">
          <div className="bg-red-500/10 p-2 rounded-lg border border-red-500/20">
            <Target className="text-red-400 animate-pulse" size={20} />
          </div>
          <div>
            <h2 className="text-sm font-bold text-white tracking-widest uppercase">
              Kill Chain Analysis
            </h2>
            <div className="flex items-center gap-2 text-[10px] text-slate-400 font-mono">
              <span
                className={`w-2 h-2 rounded-full ${chain_completion > 0 ? "bg-red-500 animate-ping" : "bg-slate-600"}`}
              />
              {chain_completion}% THREAT PROGRESSION
            </div>
          </div>
        </div>

        {/* Progress Mini-Bar */}
        <div className="w-32 h-1.5 bg-slate-800 rounded-full overflow-hidden border border-slate-700">
          <div
            className="h-full bg-gradient-to-r from-blue-500 via-amber-500 to-red-600 transition-all duration-1000 ease-out"
            style={{ width: `${chain_completion}%` }}
          />
        </div>
      </div>

      {/* ── PIPELINE VISUALIZATION ── */}
      <div className="relative flex-1 flex flex-col justify-center py-4 z-10">
        {/* Connecting Line */}
        <div className="absolute top-1/2 left-4 right-4 h-0.5 bg-slate-800 -z-10 transform -translate-y-1/2" />
        <div
          className="absolute top-1/2 left-4 h-0.5 bg-gradient-to-r from-blue-500 via-fuchsia-500 to-red-500 -z-10 transform -translate-y-1/2 transition-all duration-1000"
          style={{ width: `calc(${chain_completion}% - 2rem)` }}
        />

        <div className="grid grid-cols-5 gap-4">
          {STAGE_CONFIG.map((cfg) => {
            const stageData = stages.find((s) => s.id === cfg.id) || {
              active: false,
              count: 0,
            };
            const isActive = stageData.active;
            const isSelected = expandedStage === cfg.id;

            return (
              <div
                key={cfg.id}
                className="relative flex flex-col items-center group cursor-pointer"
                onClick={() => setExpandedStage(cfg.id)}
              >
                {/* Node */}
                <div
                  className={`
                    w-16 h-16 rounded-2xl flex items-center justify-center border transition-all duration-300 transform
                    ${
                      isActive
                        ? "bg-slate-900 scale-110"
                        : "bg-slate-950 border-slate-800 grayscale opacity-60 hover:grayscale-0 hover:opacity-100"
                    }
                    ${isSelected ? "ring-2 ring-offset-2 ring-offset-slate-950" : ""}
                  `}
                  style={{
                    borderColor: isActive ? cfg.color : undefined,
                    boxShadow: isActive ? `0 0 20px ${cfg.color}40` : undefined,
                    "--tw-ring-color": isSelected ? cfg.color : undefined,
                  }}
                >
                  <div
                    className={`transition-all duration-300 ${isActive ? "text-white drop-shadow-[0_0_8px_rgba(255,255,255,0.5)]" : "text-slate-500"}`}
                  >
                    {cfg.icon}
                  </div>

                  {/* Alert Badge */}
                  {stageData.count > 0 && (
                    <div className="absolute -top-2 -right-2 w-6 h-6 rounded-lg bg-red-600 border border-red-400 text-white text-[10px] font-bold flex items-center justify-center shadow-lg animate-bounce">
                      {stageData.count}
                    </div>
                  )}
                </div>

                {/* Label */}
                <div
                  className={`mt-3 text-center transition-all duration-300 ${isActive || isSelected ? "opacity-100 transform translate-y-0" : "opacity-60"}`}
                >
                  <div
                    className={`text-[10px] font-bold tracking-wider uppercase ${isActive ? "text-white" : "text-slate-500"}`}
                  >
                    {cfg.label}
                  </div>
                </div>

                {/* Active Indicator Line */}
                {isSelected && (
                  <div className="absolute -bottom-8 w-px h-8 bg-gradient-to-b from-slate-600 to-transparent" />
                )}
              </div>
            );
          })}
        </div>
      </div>

      {/* ── DETAILS PANEL ── */}
      <div className="h-40 bg-slate-950/50 backdrop-blur-md border border-slate-800 rounded-xl overflow-hidden flex flex-col relative z-20 shadow-2xl transition-all duration-300">
        {expandedStage ? (
          (() => {
            const cfg = STAGE_CONFIG.find((c) => c.id === expandedStage);
            const stageData = stages.find((s) => s.id === expandedStage) || {
              alerts: [],
            };

            return (
              <>
                <div className="h-0.5 w-full bg-slate-900">
                  <div
                    className={`h-full bg-gradient-to-r ${cfg.gradient}`}
                    style={{ width: "100%" }}
                  />
                </div>
                <div className="flex-1 p-3 flex gap-4">
                  {/* Left Info */}
                  <div className="w-1/4 min-w-[140px] border-r border-slate-800/50 pr-4 flex flex-col justify-center">
                    <div className="text-xl font-bold text-white mb-0.5 tracking-wide">
                      {cfg.label}
                    </div>
                    <div className="text-[10px] text-slate-400 font-mono mb-2">
                      {cfg.description}
                    </div>

                    <div className="flex items-center gap-1.5 text-[9px] text-slate-500 uppercase tracking-widest bg-slate-900/50 px-2 py-1 rounded border border-slate-800 w-fit">
                      <Activity size={10} />
                      {stageData.alerts.length} Events
                    </div>
                  </div>

                  {/* Right List */}
                  <div className="flex-1 overflow-y-auto custom-scrollbar pr-1">
                    {stageData.alerts.length > 0 ? (
                      <div className="grid grid-cols-2 gap-2">
                        {stageData.alerts.map((alert, i) => (
                          <div
                            key={i}
                            className="group flex items-center gap-2 p-2 rounded bg-slate-900/30 border border-slate-800/50 hover:bg-slate-800/50 hover:border-slate-700 transition-all"
                          >
                            <div
                              className={`w-1.5 h-1.5 rounded-full flex-none ${SEV_DOT[alert.severity] || "bg-slate-500"}`}
                            />
                            <div className="flex-1 min-w-0">
                              <div className="text-[10px] text-slate-200 font-medium truncate group-hover:text-white transition-colors">
                                {alert.description ||
                                  "Suspicious activity detected"}
                              </div>
                              <div className="text-[9px] text-slate-500 font-mono flex justify-between items-center mt-0.5">
                                <span className="truncate max-w-[80px]">
                                  {alert.source || "Unknown Source"}
                                </span>
                                <span className="opacity-50">
                                  {new Date().toLocaleTimeString([], {
                                    hour: "2-digit",
                                    minute: "2-digit",
                                  })}
                                </span>
                              </div>
                            </div>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <div className="h-full flex flex-col items-center justify-center text-slate-600 gap-1 opacity-60">
                        <ShieldAlert size={20} />
                        <span className="text-[10px] font-mono tracking-wider">
                          NO ACTIVE THREATS IN THIS STAGE
                        </span>
                      </div>
                    )}
                  </div>
                </div>
              </>
            );
          })()
        ) : (
          <div className="h-full flex items-center justify-center text-slate-600 text-xs font-mono">
            Select a stage to view details
          </div>
        )}
      </div>
    </div>
  );
};

export default KillChain;
