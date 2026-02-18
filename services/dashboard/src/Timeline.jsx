import React, { useState, useEffect, useMemo } from "react";
import { fetchTimeline, fetchAlerts } from "./api";
import {
  Clock,
  Filter,
  BarChart3,
  ShieldAlert,
  ArrowRight,
  ChevronDown,
  Zap,
  TrendingUp,
} from "lucide-react";

const SEV_COLORS = {
  HIGH: {
    bar: "#ef4444",
    text: "text-red-400",
    bg: "bg-red-500",
    badge: "bg-red-950/50 text-red-500 border-red-500/30",
  },
  MEDIUM: {
    bar: "#f59e0b",
    text: "text-amber-400",
    bg: "bg-amber-500",
    badge: "bg-amber-950/50 text-amber-500 border-amber-500/30",
  },
  LOW: {
    bar: "#3b82f6",
    text: "text-blue-400",
    bg: "bg-blue-500",
    badge: "bg-blue-950/50 text-blue-400 border-blue-500/30",
  },
};

const Timeline = ({ searchQuery }) => {
  const [timeline, setTimeline] = useState(null);
  const [alerts, setAlerts] = useState([]);
  const [filterSeverity, setFilterSeverity] = useState("ALL");
  const [filterProtocol, setFilterProtocol] = useState("ALL");
  const [filterSource, setFilterSource] = useState("ALL");
  const [showFilters, setShowFilters] = useState(false);

  useEffect(() => {
    const load = async () => {
      const [tl, al] = await Promise.all([fetchTimeline(), fetchAlerts()]);
      if (tl) setTimeline(tl);
      if (al) setAlerts(al);
    };
    load();
    const interval = setInterval(load, 5000);
    return () => clearInterval(interval);
  }, []);

  // Filtered alerts
  const filtered = useMemo(() => {
    return alerts.filter((a) => {
      if (filterSeverity !== "ALL" && a.severity !== filterSeverity)
        return false;
      if (filterProtocol !== "ALL" && a.protocol !== filterProtocol)
        return false;
      if (filterSource !== "ALL" && a.source !== filterSource) return false;
      if (searchQuery) {
        const q = searchQuery.toLowerCase();
        if (
          !a.description?.toLowerCase().includes(q) &&
          !a.source?.toLowerCase().includes(q) &&
          !a.target?.toLowerCase().includes(q)
        )
          return false;
      }
      return true;
    });
  }, [alerts, filterSeverity, filterProtocol, filterSource, searchQuery]);

  // Attack progression: group consecutive alerts by same source
  const attackPatterns = useMemo(() => {
    const chains = [];
    let current = null;

    const sorted = [...filtered].sort(
      (a, b) => new Date(a.timestamp) - new Date(b.timestamp),
    );

    for (const alert of sorted) {
      if (current && current.source === alert.source) {
        current.alerts.push(alert);
        current.endTime = alert.timestamp;
      } else {
        if (current && current.alerts.length >= 2) {
          chains.push(current);
        }
        current = {
          source: alert.source,
          alerts: [alert],
          startTime: alert.timestamp,
          endTime: alert.timestamp,
        };
      }
    }
    if (current && current.alerts.length >= 2) {
      chains.push(current);
    }

    return chains.sort((a, b) => b.alerts.length - a.alerts.length).slice(0, 5);
  }, [filtered]);

  if (!timeline) {
    return (
      <div className="h-full flex items-center justify-center text-slate-500 font-mono text-sm">
        <Clock className="w-5 h-5 mr-2 animate-spin" />
        Loading timeline…
      </div>
    );
  }

  const buckets = timeline.buckets || [];
  const maxBucket = Math.max(...buckets.map((b) => b.total), 1);

  return (
    <div className="h-full overflow-y-auto p-3 space-y-3 custom-scrollbar">
      {/* Header + Filter Toggle */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Clock size={14} className="text-cyan-400" />
          <span className="text-xs font-mono font-bold text-slate-300 uppercase tracking-widest">
            Event Timeline
          </span>
          <span className="text-[10px] font-mono text-slate-600 bg-slate-800 px-1.5 py-0.5 rounded-full border border-slate-700">
            {filtered.length} events
          </span>
        </div>
        <button
          onClick={() => setShowFilters(!showFilters)}
          className={`flex items-center gap-1 text-[10px] font-mono font-bold px-2 py-1 rounded border transition-all ${
            showFilters
              ? "text-cyan-400 bg-cyan-500/10 border-cyan-500/30"
              : "text-slate-400 bg-slate-800 border-slate-700 hover:border-slate-500"
          }`}
        >
          <Filter size={10} />
          Filters
          <ChevronDown
            size={10}
            className={`transition-transform ${showFilters ? "rotate-180" : ""}`}
          />
        </button>
      </div>

      {/* ═══ Filters Panel ═══ */}
      {showFilters && (
        <div className="bg-sh-panel border border-sh-border rounded-xl p-3 space-y-2 animate-in slide-in-from-top-2 duration-200">
          <div className="grid grid-cols-3 gap-2">
            <FilterSelect
              label="Severity"
              value={filterSeverity}
              onChange={setFilterSeverity}
              options={["ALL", "HIGH", "MEDIUM", "LOW"]}
            />
            <FilterSelect
              label="Protocol"
              value={filterProtocol}
              onChange={setFilterProtocol}
              options={["ALL", ...(timeline.filters?.protocols || [])]}
            />
            <FilterSelect
              label="Source IP"
              value={filterSource}
              onChange={setFilterSource}
              options={["ALL", ...(timeline.filters?.sources || [])]}
            />
          </div>
          {(filterSeverity !== "ALL" ||
            filterProtocol !== "ALL" ||
            filterSource !== "ALL") && (
            <button
              onClick={() => {
                setFilterSeverity("ALL");
                setFilterProtocol("ALL");
                setFilterSource("ALL");
              }}
              className="text-[9px] font-mono text-slate-500 hover:text-white transition-colors"
            >
              ✕ Clear all filters
            </button>
          )}
        </div>
      )}

      {/* ═══ Time-Series Bar Chart ═══ */}
      <div className="bg-sh-panel border border-sh-border rounded-xl overflow-hidden">
        <div className="px-4 py-2.5 border-b border-sh-border bg-slate-900/50 flex items-center gap-2">
          <BarChart3 size={12} className="text-cyan-400" />
          <span className="text-[10px] font-mono font-bold text-slate-400 uppercase tracking-widest">
            Events per Minute
          </span>
        </div>
        <div className="p-4">
          {buckets.length === 0 ? (
            <div className="text-xs text-slate-600 font-mono text-center py-6">
              No time-series data yet — waiting for events
            </div>
          ) : (
            <div className="flex items-end gap-1 h-32">
              {buckets.map((b, i) => {
                const highPct = (b.HIGH / maxBucket) * 100;
                const medPct = (b.MEDIUM / maxBucket) * 100;
                const lowPct = (b.LOW / maxBucket) * 100;
                return (
                  <div
                    key={i}
                    className="flex-1 flex flex-col items-center group relative"
                  >
                    {/* Tooltip */}
                    <div className="absolute bottom-full mb-1 hidden group-hover:flex flex-col items-center z-20">
                      <div className="bg-slate-800 border border-slate-600 rounded px-2 py-1 text-[9px] font-mono text-slate-300 whitespace-nowrap shadow-lg">
                        <div className="font-bold text-slate-200">{b.time}</div>
                        {b.HIGH > 0 && (
                          <div className="text-red-400">HIGH: {b.HIGH}</div>
                        )}
                        {b.MEDIUM > 0 && (
                          <div className="text-amber-400">MED: {b.MEDIUM}</div>
                        )}
                        {b.LOW > 0 && (
                          <div className="text-blue-400">LOW: {b.LOW}</div>
                        )}
                      </div>
                    </div>
                    {/* Stacked bar */}
                    <div className="w-full flex flex-col-reverse justify-start h-28 gap-px">
                      {b.LOW > 0 && (
                        <div
                          className="w-full rounded-t-sm bg-blue-500 transition-all duration-300"
                          style={{ height: `${lowPct}%` }}
                        />
                      )}
                      {b.MEDIUM > 0 && (
                        <div
                          className="w-full bg-amber-500 transition-all duration-300"
                          style={{ height: `${medPct}%` }}
                        />
                      )}
                      {b.HIGH > 0 && (
                        <div
                          className="w-full rounded-t-sm bg-red-500 transition-all duration-300"
                          style={{ height: `${highPct}%` }}
                        />
                      )}
                    </div>
                    {/* Time label (show every 3rd) */}
                    {(i % Math.max(1, Math.floor(buckets.length / 8)) === 0 ||
                      i === buckets.length - 1) && (
                      <span className="text-[7px] font-mono text-slate-600 mt-1 -rotate-45 origin-top-left">
                        {b.time}
                      </span>
                    )}
                  </div>
                );
              })}
            </div>
          )}
          {/* Legend */}
          <div className="flex items-center gap-4 mt-3 justify-center">
            <LegendDot color="bg-red-500" label="HIGH" />
            <LegendDot color="bg-amber-500" label="MEDIUM" />
            <LegendDot color="bg-blue-500" label="LOW" />
          </div>
        </div>
      </div>

      {/* ═══ Attack Progression Patterns ═══ */}
      {attackPatterns.length > 0 && (
        <div className="bg-sh-panel border border-sh-border rounded-xl overflow-hidden">
          <div className="px-4 py-2.5 border-b border-sh-border bg-slate-900/50 flex items-center gap-2">
            <TrendingUp size={12} className="text-amber-400" />
            <span className="text-[10px] font-mono font-bold text-slate-400 uppercase tracking-widest">
              Attack Chains
            </span>
          </div>
          <div className="p-3 space-y-2">
            {attackPatterns.map((chain, i) => (
              <div
                key={i}
                className="bg-slate-900/60 border border-sh-border/50 rounded-lg p-2.5"
              >
                <div className="flex items-center justify-between mb-1.5">
                  <div className="flex items-center gap-1.5">
                    <Zap size={10} className="text-amber-400" />
                    <span className="text-[10px] font-mono font-bold text-slate-300">
                      {chain.source}
                    </span>
                  </div>
                  <span className="text-[9px] font-mono text-slate-600">
                    {chain.alerts.length} events
                  </span>
                </div>
                {/* Mini timeline dots */}
                <div className="flex items-center gap-0.5">
                  {chain.alerts.map((a, j) => (
                    <div key={j} className="flex items-center">
                      <div
                        className={`w-2 h-2 rounded-full ${SEV_COLORS[a.severity]?.bg || "bg-slate-500"}`}
                        title={`${a.severity}: ${a.description}`}
                      />
                      {j < chain.alerts.length - 1 && (
                        <div className="w-2 h-px bg-slate-700" />
                      )}
                    </div>
                  ))}
                </div>
                <div className="text-[9px] font-mono text-slate-600 mt-1">
                  {new Date(chain.startTime).toLocaleTimeString([], {
                    hour12: false,
                  })}{" "}
                  →{" "}
                  {new Date(chain.endTime).toLocaleTimeString([], {
                    hour12: false,
                  })}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* ═══ Chronological Event Feed ═══ */}
      <div className="bg-sh-panel border border-sh-border rounded-xl overflow-hidden">
        <div className="px-4 py-2.5 border-b border-sh-border bg-slate-900/50 flex items-center gap-2">
          <ShieldAlert size={12} className="text-red-400" />
          <span className="text-[10px] font-mono font-bold text-slate-400 uppercase tracking-widest">
            Chronological Feed
          </span>
        </div>
        <div className="max-h-[400px] overflow-y-auto custom-scrollbar">
          {filtered.length === 0 ? (
            <div className="text-xs text-slate-600 font-mono text-center py-8">
              No events match current filters
            </div>
          ) : (
            <div className="relative">
              {/* Timeline line */}
              <div className="absolute left-6 top-0 bottom-0 w-px bg-sh-border/50" />

              {[...filtered]
                .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))
                .map((alert, i) => {
                  const sev = SEV_COLORS[alert.severity] || SEV_COLORS.LOW;
                  return (
                    <div
                      key={alert.id || i}
                      className="relative flex gap-3 px-4 py-2.5 hover:bg-slate-800/30 transition-colors group"
                    >
                      {/* Timeline dot */}
                      <div className="relative z-10 flex-none mt-1">
                        <div
                          className={`w-3 h-3 rounded-full border-2 border-slate-900 ${sev.bg}`}
                        />
                      </div>

                      {/* Content */}
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 mb-0.5">
                          <span
                            className={`text-[9px] font-bold px-1 py-px rounded border ${sev.badge}`}
                          >
                            {alert.severity}
                          </span>
                          <span className="text-[10px] font-mono text-slate-500">
                            {new Date(alert.timestamp).toLocaleTimeString([], {
                              hour12: false,
                            })}
                          </span>
                          {alert.protocol && (
                            <span className="text-[9px] font-mono text-slate-600 bg-slate-800 px-1 rounded">
                              {alert.protocol}
                            </span>
                          )}
                        </div>
                        <div className="text-[11px] text-slate-300 font-medium leading-relaxed">
                          {alert.description}
                        </div>
                        {alert.source && (
                          <div className="flex items-center gap-1.5 mt-1 text-[9px] font-mono text-slate-500">
                            <span className="text-blue-400">
                              {alert.source}
                            </span>
                            <ArrowRight className="w-2.5 h-2.5 text-slate-700" />
                            <span className="text-red-400">{alert.target}</span>
                          </div>
                        )}
                      </div>
                    </div>
                  );
                })}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

// ═══════════════════════════════════════
// Sub-components
// ═══════════════════════════════════════

const FilterSelect = ({ label, value, onChange, options }) => (
  <div>
    <label className="text-[8px] font-mono text-slate-600 uppercase tracking-wider block mb-0.5">
      {label}
    </label>
    <select
      value={value}
      onChange={(e) => onChange(e.target.value)}
      className="w-full bg-slate-900 border border-sh-border text-[10px] font-mono text-slate-300 rounded px-2 py-1 focus:outline-none focus:border-cyan-500/50"
    >
      {options.map((o) => (
        <option key={o} value={o}>
          {o}
        </option>
      ))}
    </select>
  </div>
);

const LegendDot = ({ color, label }) => (
  <div className="flex items-center gap-1">
    <div className={`w-2 h-2 rounded-sm ${color}`} />
    <span className="text-[9px] font-mono text-slate-500">{label}</span>
  </div>
);

export default Timeline;
