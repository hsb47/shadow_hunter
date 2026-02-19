import React, { useState, useEffect } from "react";
import { fetchSessions } from "./api";
import {
  Layers,
  Clock,
  ChevronRight,
  AlertTriangle,
  Globe,
  ArrowRight,
  Zap,
  Target,
} from "lucide-react";

const SEV = {
  HIGH: {
    bg: "bg-red-500",
    text: "text-red-400",
    badge: "bg-red-950/50 text-red-400 border-red-500/30",
    dot: "#ef4444",
  },
  MEDIUM: {
    bg: "bg-amber-500",
    text: "text-amber-400",
    badge: "bg-amber-950/50 text-amber-400 border-amber-500/30",
    dot: "#f59e0b",
  },
  LOW: {
    bg: "bg-blue-500",
    text: "text-blue-400",
    badge: "bg-blue-950/50 text-blue-400 border-blue-500/30",
    dot: "#3b82f6",
  },
};

const SessionTracking = ({ searchQuery, onNavigateToNode }) => {
  const [sessions, setSessions] = useState([]);
  const [expandedId, setExpandedId] = useState(null);

  useEffect(() => {
    const load = async () => {
      const data = await fetchSessions();
      if (data) setSessions(data);
    };
    load();
    const interval = setInterval(load, 8000);
    return () => clearInterval(interval);
  }, []);

  const filtered = sessions.filter((s) => {
    if (!searchQuery) return true;
    const q = searchQuery.toLowerCase();
    return (
      s.source.toLowerCase().includes(q) ||
      s.label.toLowerCase().includes(q) ||
      s.destinations.some((d) => d.toLowerCase().includes(q))
    );
  });

  const totalRisk = sessions.reduce((s, x) => s + x.risk_score, 0);
  const totalSessions = sessions.length;
  const highRiskCount = sessions.filter(
    (s) => s.max_severity === "HIGH",
  ).length;

  const fmtDuration = (secs) => {
    if (secs < 60) return `${secs}s`;
    if (secs < 3600) return `${Math.floor(secs / 60)}m ${secs % 60}s`;
    return `${Math.floor(secs / 3600)}h ${Math.floor((secs % 3600) / 60)}m`;
  };

  return (
    <div className="h-full overflow-y-auto space-y-3 custom-scrollbar">
      {/* Header */}
      <div className="flex items-center gap-2">
        <Layers size={14} className="text-violet-400" />
        <span className="text-xs font-mono font-bold text-slate-300 uppercase tracking-widest">
          Session Tracking
        </span>
        <span className="text-[10px] font-mono text-slate-600 bg-slate-800 px-1.5 py-0.5 rounded-full border border-slate-700">
          {filtered.length} sessions
        </span>
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-3 gap-2">
        <SummaryCard
          label="Active Sessions"
          value={totalSessions}
          color="text-violet-400"
        />
        <SummaryCard
          label="High Risk"
          value={highRiskCount}
          color="text-red-400"
        />
        <SummaryCard
          label="Total Risk"
          value={totalRisk}
          color="text-amber-400"
        />
      </div>

      {/* Sessions List */}
      {filtered.length === 0 ? (
        <div className="h-48 flex flex-col items-center justify-center text-slate-600">
          <Layers className="w-12 h-12 mb-2 stroke-1" />
          <span className="text-xs font-mono uppercase tracking-widest">
            {searchQuery ? "No matching sessions" : "No session data yet"}
          </span>
        </div>
      ) : (
        <div className="space-y-2">
          {filtered.map((session) => {
            const isExpanded = expandedId === session.id;
            const sev = SEV[session.max_severity] || SEV.LOW;

            return (
              <div
                key={session.id}
                className={`bg-sh-panel border rounded-xl overflow-hidden transition-all ${
                  isExpanded
                    ? "border-violet-500/50 shadow-[0_0_20px_rgba(139,92,246,0.1)]"
                    : "border-sh-border hover:border-slate-600"
                }`}
              >
                {/* Session Header */}
                <div
                  className="p-3 cursor-pointer"
                  onClick={() => setExpandedId(isExpanded ? null : session.id)}
                >
                  <div className="flex items-center gap-3">
                    {/* Severity Indicator */}
                    <div
                      className={`w-2 h-full min-h-[40px] rounded-full ${sev.bg}`}
                      style={{ boxShadow: `0 0 8px ${sev.dot}40` }}
                    />

                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 mb-1">
                        <span className="text-xs font-mono font-bold text-slate-200">
                          {session.source}
                        </span>
                        <ArrowRight size={10} className="text-slate-600" />
                        <span className="text-[10px] font-mono text-slate-400 truncate">
                          {session.destinations.length > 1
                            ? `${session.destinations[0]} +${session.destinations.length - 1}`
                            : session.destinations[0] || "—"}
                        </span>
                      </div>

                      <div className="flex items-center gap-2 flex-wrap">
                        <span
                          className={`text-[9px] font-bold px-1 py-px rounded border ${sev.badge}`}
                        >
                          {session.max_severity}
                        </span>
                        <span className="text-[10px] font-mono text-slate-500">
                          {session.alert_count} events
                        </span>
                        <span className="text-[10px] font-mono text-slate-600">
                          •
                        </span>
                        <span className="text-[10px] font-mono text-slate-500">
                          <Clock size={9} className="inline mr-0.5" />
                          {fmtDuration(session.duration_seconds)}
                        </span>
                        <span className="text-[10px] font-mono text-violet-400">
                          Risk: {session.risk_score}
                        </span>
                      </div>
                    </div>

                    {/* Label */}
                    <span className="text-[9px] font-mono font-bold px-1.5 py-0.5 rounded bg-violet-500/10 text-violet-400 border border-violet-500/20">
                      {session.label}
                    </span>

                    <ChevronRight
                      size={14}
                      className={`text-slate-600 transition-transform flex-none ${isExpanded ? "rotate-90" : ""}`}
                    />
                  </div>
                </div>

                {/* ═══ Expanded Session Detail ═══ */}
                {isExpanded && (
                  <div className="border-t border-sh-border/50 p-3 space-y-3 bg-slate-900/30">
                    {/* Session Metadata */}
                    <div className="grid grid-cols-2 lg:grid-cols-4 gap-2">
                      <MetaCard
                        label="Start"
                        value={
                          session.start_time
                            ? new Date(session.start_time).toLocaleTimeString(
                                [],
                                { hour12: false },
                              )
                            : "—"
                        }
                      />
                      <MetaCard
                        label="End"
                        value={
                          session.end_time
                            ? new Date(session.end_time).toLocaleTimeString(
                                [],
                                { hour12: false },
                              )
                            : "—"
                        }
                      />
                      <MetaCard
                        label="Duration"
                        value={fmtDuration(session.duration_seconds)}
                      />
                      <MetaCard
                        label="Risk Score"
                        value={session.risk_score}
                        valueClass="text-violet-400"
                      />
                    </div>

                    {/* Severity Breakdown */}
                    <div>
                      <SectionTitle
                        icon={<AlertTriangle size={11} />}
                        text="Severity"
                      />
                      <div className="flex gap-3 mt-1">
                        {["HIGH", "MEDIUM", "LOW"].map((s) => (
                          <div
                            key={s}
                            className="flex items-center gap-1.5 text-[10px] font-mono"
                          >
                            <div
                              className={`w-2 h-2 rounded-sm ${SEV[s].bg}`}
                            />
                            <span className={SEV[s].text}>
                              {session.severity_breakdown[s] || 0}
                            </span>
                            <span className="text-slate-600">{s}</span>
                          </div>
                        ))}
                      </div>
                    </div>

                    {/* Destinations */}
                    <div>
                      <SectionTitle
                        icon={<Globe size={11} />}
                        text="Destinations"
                      />
                      <div className="flex flex-wrap gap-1.5 mt-1">
                        {session.destinations.map((d, i) => (
                          <span
                            key={i}
                            className="text-[10px] font-mono text-slate-300 bg-slate-800 border border-slate-700 px-1.5 py-0.5 rounded cursor-pointer hover:text-cyan-400 hover:border-cyan-500/30 transition-colors"
                            onClick={(e) => {
                              e.stopPropagation();
                              if (onNavigateToNode) onNavigateToNode(d);
                            }}
                          >
                            {d}
                          </span>
                        ))}
                      </div>
                    </div>

                    {/* Session Timeline */}
                    <div>
                      <SectionTitle
                        icon={<Zap size={11} />}
                        text="Activity Timeline"
                      />
                      <div className="relative mt-2 ml-3 border-l border-slate-700 pl-4 space-y-2">
                        {session.timeline.map((evt, i) => {
                          const evtSev = SEV[evt.severity] || SEV.LOW;
                          return (
                            <div key={i} className="relative">
                              {/* Timeline dot */}
                              <div
                                className={`absolute -left-[21px] top-1 w-2.5 h-2.5 rounded-full border-2 border-slate-900 ${evtSev.bg}`}
                                style={{ boxShadow: `0 0 6px ${evtSev.dot}60` }}
                              />
                              <div className="flex items-start gap-2">
                                <span className="text-[9px] font-mono text-slate-600 flex-none w-12">
                                  {evt.timestamp
                                    ? new Date(
                                        evt.timestamp,
                                      ).toLocaleTimeString([], {
                                        hour12: false,
                                        hour: "2-digit",
                                        minute: "2-digit",
                                        second: "2-digit",
                                      })
                                    : "—"}
                                </span>
                                <span className="text-[10px] text-slate-400 leading-snug">
                                  {evt.description}
                                </span>
                              </div>
                            </div>
                          );
                        })}
                      </div>
                    </div>

                    {/* Navigate */}
                    {onNavigateToNode && (
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          onNavigateToNode(session.source);
                        }}
                        className="w-full flex items-center justify-center gap-1.5 text-[10px] font-mono font-bold text-violet-400 bg-violet-500/10 hover:bg-violet-500/20 border border-violet-500/30 rounded-lg py-1.5 transition-all"
                      >
                        <Target size={10} />
                        View Source in Graph
                      </button>
                    )}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
};

// ═══ Sub-components ═══

const SummaryCard = ({ label, value, color }) => (
  <div className="bg-sh-panel border border-sh-border rounded-lg p-2.5 text-center">
    <div className={`text-lg font-mono font-bold ${color}`}>{value}</div>
    <div className="text-[8px] font-mono text-slate-500 uppercase tracking-wider">
      {label}
    </div>
  </div>
);

const MetaCard = ({ label, value, valueClass = "text-slate-300" }) => (
  <div className="bg-slate-950/50 border border-sh-border/30 rounded px-2 py-1">
    <div className="text-[8px] font-mono text-slate-600 uppercase tracking-wider">
      {label}
    </div>
    <div className={`text-[11px] font-mono ${valueClass}`}>{value}</div>
  </div>
);

const SectionTitle = ({ icon, text }) => (
  <div className="flex items-center gap-1.5">
    <span className="text-slate-500">{icon}</span>
    <span className="text-[9px] font-mono font-bold text-slate-500 uppercase tracking-widest">
      {text}
    </span>
  </div>
);

export default SessionTracking;
