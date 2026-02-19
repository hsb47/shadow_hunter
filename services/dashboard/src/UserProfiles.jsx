import React, { useState, useEffect } from "react";
import { fetchProfiles } from "./api";
import {
  User,
  Clock,
  Target,
  AlertTriangle,
  ChevronRight,
  Shield,
  Activity,
  Zap,
  Globe,
} from "lucide-react";

const SEV_COLORS = {
  HIGH: { bg: "bg-red-500", text: "text-red-400", bar: "#ef4444" },
  MEDIUM: { bg: "bg-amber-500", text: "text-amber-400", bar: "#f59e0b" },
  LOW: { bg: "bg-blue-500", text: "text-blue-400", bar: "#3b82f6" },
};

const ANOMALY_ICONS = {
  unusual_hours: <Clock size={10} className="text-amber-400" />,
  single_target_focus: <Target size={10} className="text-red-400" />,
  high_severity_ratio: <AlertTriangle size={10} className="text-red-400" />,
};

const UserProfiles = ({ searchQuery, onNavigateToNode }) => {
  const [profiles, setProfiles] = useState([]);
  const [selectedProfile, setSelectedProfile] = useState(null);

  useEffect(() => {
    const load = async () => {
      const data = await fetchProfiles();
      if (data) setProfiles(data);
    };
    load();
    const interval = setInterval(load, 8000);
    return () => clearInterval(interval);
  }, []);

  const filtered = profiles.filter((p) => {
    if (!searchQuery) return true;
    return p.ip.toLowerCase().includes(searchQuery.toLowerCase());
  });

  return (
    <div className="h-full overflow-y-auto p-3 space-y-3 custom-scrollbar">
      {/* Header */}
      <div className="flex items-center gap-2">
        <User size={14} className="text-cyan-400" />
        <span className="text-xs font-mono font-bold text-slate-300 uppercase tracking-widest">
          User Profiles
        </span>
        <span className="text-[10px] font-mono text-slate-600 bg-slate-800 px-1.5 py-0.5 rounded-full border border-slate-700">
          {filtered.length} users
        </span>
      </div>

      {filtered.length === 0 ? (
        <div className="h-64 flex flex-col items-center justify-center text-slate-600">
          <User className="w-12 h-12 mb-2 stroke-1" />
          <span className="text-xs font-mono uppercase tracking-widest">
            {searchQuery ? "No matching users" : "No user data yet"}
          </span>
        </div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
          {filtered.map((profile) => {
            const isSelected = selectedProfile?.ip === profile.ip;
            const maxRisk = Math.max(...profiles.map((p) => p.risk_score), 1);
            const riskPct = Math.round((profile.risk_score / maxRisk) * 100);

            return (
              <div
                key={profile.ip}
                onClick={() => setSelectedProfile(isSelected ? null : profile)}
                className={`bg-sh-panel border rounded-xl overflow-hidden cursor-pointer transition-all ${
                  isSelected
                    ? "border-cyan-500/50 shadow-[0_0_20px_rgba(6,182,212,0.1)]"
                    : "border-sh-border hover:border-slate-600"
                }`}
              >
                {/* Profile Header */}
                <div className="p-3 flex items-center gap-3">
                  {/* Avatar */}
                  <div
                    className={`w-10 h-10 rounded-lg flex items-center justify-center font-mono font-bold text-sm ${
                      riskPct > 70
                        ? "bg-red-500/15 text-red-400 border border-red-500/30"
                        : riskPct > 40
                          ? "bg-amber-500/15 text-amber-400 border border-amber-500/30"
                          : "bg-blue-500/15 text-blue-400 border border-blue-500/30"
                    }`}
                  >
                    {profile.ip.split(".").pop() || "?"}
                  </div>

                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="text-xs font-mono font-bold text-slate-200 truncate">
                        {profile.ip}
                      </span>
                      {profile.anomalies.length > 0 && (
                        <span className="text-[8px] font-mono font-bold px-1 py-0.5 rounded bg-red-500/15 text-red-400 border border-red-500/30">
                          {profile.anomalies.length} ANOMALY
                        </span>
                      )}
                    </div>
                    <div className="text-[10px] font-mono text-slate-500">
                      {profile.alert_count} alerts • Risk: {profile.risk_score}
                    </div>
                  </div>

                  <ChevronRight
                    size={14}
                    className={`text-slate-600 transition-transform ${isSelected ? "rotate-90" : ""}`}
                  />
                </div>

                {/* Risk Bar */}
                <div className="px-3 pb-2">
                  <div className="w-full bg-slate-800 rounded-full h-1.5">
                    <div
                      className={`h-1.5 rounded-full transition-all duration-500 ${
                        riskPct > 70
                          ? "bg-red-500"
                          : riskPct > 40
                            ? "bg-amber-500"
                            : "bg-blue-500"
                      }`}
                      style={{ width: `${riskPct}%` }}
                    />
                  </div>
                </div>

                {/* ═══ Expanded Profile Detail ═══ */}
                {isSelected && (
                  <div className="border-t border-sh-border/50 p-3 space-y-3 bg-slate-900/30">
                    {/* Activity Window */}
                    <DetailSection
                      icon={<Clock size={11} />}
                      title="Activity Window"
                    >
                      <div className="grid grid-cols-2 gap-2">
                        <MetaField
                          label="First Seen"
                          value={
                            profile.first_seen
                              ? new Date(profile.first_seen).toLocaleTimeString(
                                  [],
                                  { hour12: false },
                                )
                              : "—"
                          }
                        />
                        <MetaField
                          label="Last Seen"
                          value={
                            profile.last_seen
                              ? new Date(profile.last_seen).toLocaleTimeString(
                                  [],
                                  { hour12: false },
                                )
                              : "—"
                          }
                        />
                      </div>
                    </DetailSection>

                    {/* Hour Distribution Heatmap */}
                    <DetailSection
                      icon={<Activity size={11} />}
                      title="Hour Distribution"
                    >
                      <div className="flex gap-px">
                        {Array.from({ length: 24 }, (_, h) => {
                          const count =
                            profile.hour_distribution?.[String(h)] || 0;
                          const maxH = Math.max(
                            ...Object.values(profile.hour_distribution || {}),
                            1,
                          );
                          const intensity = count / maxH;
                          return (
                            <div
                              key={h}
                              className="flex-1 group relative"
                              title={`${h}:00 — ${count} alerts`}
                            >
                              <div
                                className="w-full h-5 rounded-sm transition-all"
                                style={{
                                  backgroundColor:
                                    count === 0
                                      ? "rgb(30,41,59)"
                                      : `rgba(6,182,212,${0.2 + intensity * 0.8})`,
                                }}
                              />
                              {h % 6 === 0 && (
                                <span className="text-[7px] font-mono text-slate-600 block text-center mt-0.5">
                                  {h}h
                                </span>
                              )}
                            </div>
                          );
                        })}
                      </div>
                    </DetailSection>

                    {/* Top Destinations */}
                    <DetailSection
                      icon={<Globe size={11} />}
                      title="Frequent Destinations"
                    >
                      <div className="space-y-1">
                        {profile.top_destinations.map((d, i) => (
                          <div
                            key={i}
                            className="flex items-center gap-2 text-[10px] font-mono"
                          >
                            <span className="text-slate-600 w-3">{i + 1}.</span>
                            <span
                              className="text-slate-300 truncate flex-1 cursor-pointer hover:text-cyan-400 transition-colors"
                              onClick={(e) => {
                                e.stopPropagation();
                                if (onNavigateToNode)
                                  onNavigateToNode(d.target);
                              }}
                            >
                              {d.target}
                            </span>
                            <span className="text-slate-500 flex-none">
                              {d.count}×
                            </span>
                          </div>
                        ))}
                      </div>
                    </DetailSection>

                    {/* Severity Breakdown */}
                    <DetailSection
                      icon={<Shield size={11} />}
                      title="Severity Breakdown"
                    >
                      <div className="flex gap-3">
                        {["HIGH", "MEDIUM", "LOW"].map((sev) => {
                          const count = profile.severity_breakdown[sev] || 0;
                          return (
                            <div
                              key={sev}
                              className="flex items-center gap-1.5 text-[10px] font-mono"
                            >
                              <div
                                className={`w-2 h-2 rounded-sm ${SEV_COLORS[sev].bg}`}
                              />
                              <span className={SEV_COLORS[sev].text}>
                                {count}
                              </span>
                              <span className="text-slate-600">{sev}</span>
                            </div>
                          );
                        })}
                      </div>
                    </DetailSection>

                    {/* Anomalies */}
                    {profile.anomalies.length > 0 && (
                      <DetailSection
                        icon={<Zap size={11} />}
                        title="Behavioral Anomalies"
                      >
                        <div className="space-y-1.5">
                          {profile.anomalies.map((a, i) => (
                            <div
                              key={i}
                              className="flex items-center gap-2 bg-red-500/5 border border-red-500/20 rounded px-2 py-1.5"
                            >
                              {ANOMALY_ICONS[a.type] || (
                                <AlertTriangle
                                  size={10}
                                  className="text-amber-400"
                                />
                              )}
                              <span className="text-[10px] font-mono text-slate-300">
                                {a.detail}
                              </span>
                            </div>
                          ))}
                        </div>
                      </DetailSection>
                    )}

                    {/* Navigate */}
                    {onNavigateToNode && (
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          onNavigateToNode(profile.ip);
                        }}
                        className="w-full flex items-center justify-center gap-1.5 text-[10px] font-mono font-bold text-cyan-400 bg-cyan-500/10 hover:bg-cyan-500/20 border border-cyan-500/30 rounded-lg py-1.5 transition-all"
                      >
                        <Target size={10} />
                        View in Graph
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

// ═══════════════════════════════════════
// Sub-components
// ═══════════════════════════════════════

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
    <div className="text-[11px] font-mono text-slate-300">{value}</div>
  </div>
);

export default UserProfiles;
