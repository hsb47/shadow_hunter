import React, { useState, useEffect } from "react";
import { fetchCompliance } from "./api";
import {
  ShieldCheck,
  ShieldX,
  AlertTriangle,
  CheckCircle,
  XCircle,
  ChevronRight,
} from "lucide-react";

const STATUS_STYLES = {
  pass: {
    icon: <CheckCircle size={14} />,
    color: "text-emerald-400",
    bg: "bg-emerald-500/10",
    border: "border-emerald-500/30",
    label: "PASS",
  },
  warn: {
    icon: <AlertTriangle size={14} />,
    color: "text-amber-400",
    bg: "bg-amber-500/10",
    border: "border-amber-500/30",
    label: "WARN",
  },
  fail: {
    icon: <XCircle size={14} />,
    color: "text-red-400",
    bg: "bg-red-500/10",
    border: "border-red-500/30",
    label: "FAIL",
  },
};

const ComplianceBoard = () => {
  const [data, setData] = useState({
    frameworks: [],
    overall_score: 0,
    total_checks: 0,
    violations: 0,
  });
  const [expandedFw, setExpandedFw] = useState(null);

  useEffect(() => {
    const load = async () => {
      const result = await fetchCompliance();
      if (result) setData(result);
    };
    load();
    const interval = setInterval(load, 10000);
    return () => clearInterval(interval);
  }, []);

  const { frameworks, overall_score, total_checks, violations } = data;

  const scoreColor =
    overall_score >= 80
      ? "text-emerald-400"
      : overall_score >= 60
        ? "text-amber-400"
        : "text-red-400";

  return (
    <div className="h-full overflow-y-auto space-y-4 custom-scrollbar">
      {/* Header */}
      <div className="flex items-center gap-2">
        <ShieldCheck size={14} className="text-emerald-400" />
        <span className="text-xs font-mono font-bold text-slate-300 uppercase tracking-widest">
          Compliance Scoreboard
        </span>
      </div>

      {/* Overall Score Gauge */}
      <div className="bg-sh-panel border border-sh-border rounded-xl p-5 text-center">
        <div className="relative w-28 h-28 mx-auto mb-3">
          {/* SVG Gauge */}
          <svg viewBox="0 0 120 120" className="w-full h-full -rotate-90">
            <circle
              cx="60"
              cy="60"
              r="50"
              fill="none"
              stroke="currentColor"
              className="text-slate-800"
              strokeWidth="8"
            />
            <circle
              cx="60"
              cy="60"
              r="50"
              fill="none"
              stroke="currentColor"
              className={scoreColor}
              strokeWidth="8"
              strokeLinecap="round"
              strokeDasharray={`${overall_score * 3.14} 314`}
              style={{
                transition: "stroke-dasharray 1s ease-out",
                filter: `drop-shadow(0 0 6px currentColor)`,
              }}
            />
          </svg>
          <div className="absolute inset-0 flex flex-col items-center justify-center">
            <span className={`text-2xl font-mono font-bold ${scoreColor}`}>
              {overall_score}%
            </span>
            <span className="text-[8px] font-mono text-slate-500 uppercase tracking-wider">
              Compliant
            </span>
          </div>
        </div>

        <div className="flex justify-center gap-4 text-[10px] font-mono">
          <span className="text-slate-500">
            <span className="text-emerald-400 font-bold">
              {total_checks - violations}
            </span>{" "}
            passed
          </span>
          <span className="text-slate-500">
            <span className="text-red-400 font-bold">{violations}</span>{" "}
            violations
          </span>
        </div>
      </div>

      {/* Framework Cards */}
      <div className="space-y-2">
        {frameworks.map((fw) => {
          const isExpanded = expandedFw === fw.id;
          const fwScoreColor =
            fw.score >= 80
              ? "text-emerald-400"
              : fw.score >= 60
                ? "text-amber-400"
                : "text-red-400";

          return (
            <div
              key={fw.id}
              className={`bg-sh-panel border rounded-xl overflow-hidden transition-all ${
                isExpanded
                  ? "border-emerald-500/30"
                  : "border-sh-border hover:border-slate-600"
              }`}
            >
              <div
                className="p-3 cursor-pointer flex items-center gap-3"
                onClick={() => setExpandedFw(isExpanded ? null : fw.id)}
              >
                {/* Score mini-gauge */}
                <div className="relative w-10 h-10 flex-none">
                  <svg viewBox="0 0 40 40" className="w-full h-full -rotate-90">
                    <circle
                      cx="20"
                      cy="20"
                      r="16"
                      fill="none"
                      stroke="currentColor"
                      className="text-slate-800"
                      strokeWidth="3"
                    />
                    <circle
                      cx="20"
                      cy="20"
                      r="16"
                      fill="none"
                      stroke="currentColor"
                      className={fwScoreColor}
                      strokeWidth="3"
                      strokeLinecap="round"
                      strokeDasharray={`${fw.score} 100`}
                    />
                  </svg>
                  <span
                    className={`absolute inset-0 flex items-center justify-center text-[9px] font-mono font-bold ${fwScoreColor}`}
                  >
                    {fw.score}
                  </span>
                </div>

                <div className="flex-1 min-w-0">
                  <div className="text-xs font-mono font-bold text-slate-200">
                    {fw.name}
                  </div>
                  <div className="text-[10px] text-slate-500 truncate">
                    {fw.description}
                  </div>
                </div>

                {/* Status counts */}
                <div className="flex gap-1.5">
                  {fw.pass_count > 0 && (
                    <span className="text-[9px] font-mono font-bold text-emerald-400 bg-emerald-500/10 px-1 rounded">
                      {fw.pass_count}✓
                    </span>
                  )}
                  {fw.warn_count > 0 && (
                    <span className="text-[9px] font-mono font-bold text-amber-400 bg-amber-500/10 px-1 rounded">
                      {fw.warn_count}⚠
                    </span>
                  )}
                  {fw.fail_count > 0 && (
                    <span className="text-[9px] font-mono font-bold text-red-400 bg-red-500/10 px-1 rounded">
                      {fw.fail_count}✗
                    </span>
                  )}
                </div>

                <ChevronRight
                  size={14}
                  className={`text-slate-600 transition-transform flex-none ${isExpanded ? "rotate-90" : ""}`}
                />
              </div>

              {/* Expanded Checks */}
              {isExpanded && (
                <div className="border-t border-sh-border/50 p-2 space-y-1 bg-slate-900/30">
                  {fw.checks.map((check, i) => {
                    const st =
                      STATUS_STYLES[check.status] || STATUS_STYLES.warn;
                    return (
                      <div
                        key={i}
                        className={`flex items-center gap-2.5 px-2.5 py-2 rounded-lg ${st.bg} border ${st.border}`}
                      >
                        <span className={st.color}>{st.icon}</span>
                        <div className="flex-1 min-w-0">
                          <div className="text-[10px] font-mono font-bold text-slate-300">
                            {check.name}
                          </div>
                          <div className="text-[9px] text-slate-500">
                            {check.detail}
                          </div>
                        </div>
                        <span
                          className={`text-[8px] font-mono font-bold ${st.color}`}
                        >
                          {st.label}
                        </span>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
};

export default ComplianceBoard;
