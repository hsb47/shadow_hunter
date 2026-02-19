import React, { useState, useEffect } from "react";
import { fetchBriefing } from "./api";
import {
  FileText,
  AlertTriangle,
  Shield,
  Target,
  ListChecks,
  RefreshCw,
} from "lucide-react";

const THREAT_BADGE = {
  CRITICAL: {
    color: "text-red-400",
    bg: "bg-red-500/10",
    border: "border-red-500/30",
  },
  HIGH: {
    color: "text-orange-400",
    bg: "bg-orange-500/10",
    border: "border-orange-500/30",
  },
  ELEVATED: {
    color: "text-amber-400",
    bg: "bg-amber-500/10",
    border: "border-amber-500/30",
  },
  LOW: {
    color: "text-emerald-400",
    bg: "bg-emerald-500/10",
    border: "border-emerald-500/30",
  },
};

const SECTION_ICONS = {
  overview: <Shield size={14} />,
  shadow_ai: <AlertTriangle size={14} />,
  actor: <Target size={14} />,
  recommendations: <ListChecks size={14} />,
  status: <Shield size={14} />,
};

const SECTION_COLORS = {
  overview: "text-blue-400 border-blue-500/30",
  shadow_ai: "text-amber-400 border-amber-500/30",
  actor: "text-red-400 border-red-500/30",
  recommendations: "text-emerald-400 border-emerald-500/30",
  status: "text-slate-400 border-slate-500/30",
};

const ExecutiveBriefing = () => {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(false);

  const loadBriefing = async () => {
    setLoading(true);
    const result = await fetchBriefing();
    if (result) setData(result);
    setLoading(false);
  };

  useEffect(() => {
    loadBriefing();
  }, []);

  if (!data) {
    return (
      <div className="h-48 flex items-center justify-center text-slate-600">
        <RefreshCw className="w-6 h-6 animate-spin" />
      </div>
    );
  }

  const threat = THREAT_BADGE[data.threat_level] || THREAT_BADGE.LOW;

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <FileText size={14} className="text-blue-400" />
          <span className="text-xs font-mono font-bold text-slate-300 uppercase tracking-widest">
            Executive Threat Briefing
          </span>
        </div>
        <div className="flex items-center gap-2">
          <span
            className={`text-[9px] font-mono font-bold px-2 py-0.5 rounded-full border ${threat.bg} ${threat.color} ${threat.border}`}
          >
            {data.threat_level}
          </span>
          <button
            onClick={loadBriefing}
            disabled={loading}
            className="text-slate-500 hover:text-blue-400 transition-colors"
          >
            <RefreshCw size={12} className={loading ? "animate-spin" : ""} />
          </button>
        </div>
      </div>

      {/* Briefing Metadata */}
      <div className="flex gap-3 text-[9px] font-mono text-slate-600">
        <span>
          Generated:{" "}
          {data.generated_at
            ? new Date(data.generated_at).toLocaleString([], {
                dateStyle: "short",
                timeStyle: "medium",
              })
            : "—"}
        </span>
        <span>Period: {data.period}</span>
      </div>

      {/* Stats Bar */}
      {data.stats && (
        <div className="grid grid-cols-5 gap-2">
          <StatBox
            label="Events"
            value={data.stats.total_events}
            color="text-blue-400"
          />
          <StatBox
            label="High Sev"
            value={data.stats.high_severity}
            color="text-red-400"
          />
          <StatBox
            label="Shadow AI"
            value={data.stats.shadow_ai}
            color="text-amber-400"
          />
          <StatBox
            label="Sources"
            value={data.stats.unique_sources}
            color="text-cyan-400"
          />
          <StatBox
            label="Targets"
            value={data.stats.unique_targets}
            color="text-violet-400"
          />
        </div>
      )}

      {/* Briefing Sections */}
      <div className="space-y-3">
        {data.paragraphs.map((para, i) => {
          const sectionColor =
            SECTION_COLORS[para.type] || SECTION_COLORS.status;
          const icon = SECTION_ICONS[para.type] || SECTION_ICONS.status;

          return (
            <div
              key={i}
              className={`bg-sh-panel border rounded-xl p-4 ${sectionColor.split(" ")[1]}`}
            >
              {/* Section Header */}
              {para.title && (
                <div className="flex items-center gap-2 mb-2">
                  <span className={sectionColor.split(" ")[0]}>{icon}</span>
                  <span className="text-xs font-mono font-bold text-slate-300 uppercase tracking-wider">
                    {para.title}
                  </span>
                </div>
              )}

              {/* Text Content */}
              {para.text && (
                <p className="text-[11px] leading-relaxed text-slate-400 font-mono">
                  {para.text}
                </p>
              )}

              {/* Recommendations List */}
              {para.items && (
                <ul className="space-y-1.5 mt-1">
                  {para.items.map((item, j) => (
                    <li
                      key={j}
                      className="flex items-start gap-2 text-[11px] font-mono text-slate-400"
                    >
                      <span className="text-emerald-400 mt-0.5 flex-none">
                        ▸
                      </span>
                      {item}
                    </li>
                  ))}
                </ul>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
};

const StatBox = ({ label, value, color }) => (
  <div className="bg-sh-panel border border-sh-border rounded-lg p-2 text-center">
    <div className={`text-sm font-mono font-bold ${color}`}>{value}</div>
    <div className="text-[7px] font-mono text-slate-600 uppercase tracking-wider">
      {label}
    </div>
  </div>
);

export default ExecutiveBriefing;
