import React, { useState, useEffect } from "react";
import GraphView from "./GraphView";
import Alerts from "./Alerts";
import TrafficAnalytics from "./TrafficAnalytics";
import Timeline from "./Timeline";
import UserProfiles from "./UserProfiles";
import SessionTracking from "./SessionTracking";
import PolicyEngine from "./PolicyEngine";
import DlpMonitor from "./DlpMonitor";
import KillChain from "./KillChain";
import ComplianceBoard from "./ComplianceBoard";
import ExecutiveBriefing from "./ExecutiveBriefing";
import { generatePdfReport } from "./generatePdfReport";
import {
  fetchGraphData,
  fetchAlerts,
  fetchRiskScores,
  fetchReport,
  fetchStatus,
} from "./api";
import {
  Shield,
  Activity,
  Lock,
  Cpu,
  Globe,
  LayoutDashboard,
  Network,
  Settings,
  Bell,
  Search,
  AlertTriangle,
  Server,
  Wifi,
  Eye,
  ArrowRight,
  ChevronRight,
  Monitor,
  Database,
  Radio,
  TrendingUp,
  Download,
  BarChart2,
  Clock,
  Layers,
  ShieldAlert,
  CheckSquare,
  Sun,
  Moon,
} from "lucide-react";

function App() {
  const [time, setTime] = useState(new Date());
  const [activeTab, setActiveTab] = useState("dashboard");
  const [stats, setStats] = useState({
    nodes: 0,
    edges: 0,
    alerts: 0,
    shadowCount: 0,
  });
  const [nodeList, setNodeList] = useState([]);
  const [alertCount, setAlertCount] = useState(0);
  const lastAlertCountRef = React.useRef(0); // Track for notifications to avoid stale closures
  const [riskScores, setRiskScores] = useState([]);
  const [isLiveMode, setIsLiveMode] = useState(false);
  const [searchQuery, setSearchQuery] = useState("");
  const [darkMode, setDarkMode] = useState(true);

  // Theme toggle
  const toggleTheme = () => {
    const next = !darkMode;
    setDarkMode(next);
    if (next) {
      document.documentElement.classList.remove("light");
    } else {
      document.documentElement.classList.add("light");
    }
  };

  // Helper: Download CSV
  const downloadCSV = (data, filename) => {
    const headers = Object.keys(data[0]);
    const rows = data.map((row) =>
      headers.map((header) => JSON.stringify(row[header] || "")).join(","),
    );
    const csvContent = [headers.join(","), ...rows].join("\n");
    const blob = new Blob([csvContent], { type: "text/csv" });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    a.click();
  };

  // Fetch system mode once on mount
  useEffect(() => {
    fetchStatus().then((s) => setIsLiveMode(s.mode === "live"));

    // Request notification permission
    if ("Notification" in window && Notification.permission !== "granted") {
      Notification.requestPermission();
    }
  }, []);

  // Real-time clock
  useEffect(() => {
    const timer = setInterval(() => setTime(new Date()), 1000);
    return () => clearInterval(timer);
  }, []);

  // Fetch stats function (extracted for reuse)
  const fetchStats = async () => {
    try {
      const [graphData, alertsData, scores] = await Promise.all([
        fetchGraphData(),
        fetchAlerts(),
        fetchRiskScores(),
      ]);
      const shadowNodes = graphData.nodes.filter(
        (n) => n.data.type === "shadow",
      );
      setStats({
        nodes: graphData.nodes.length,
        edges: graphData.edges.length,
        alerts: alertsData.length,
        shadowCount: shadowNodes.length,
      });
      setNodeList(graphData.nodes.map((n) => n.data));
      setRiskScores(scores);

      // Notification check using Ref to avoid stale closure in WS callback
      const currentCount = lastAlertCountRef.current;
      if (alertsData.length > currentCount) {
        const newAlerts = alertsData.slice(0, alertsData.length - currentCount);
        const highSev = newAlerts.find((a) => a.severity === "HIGH");
        if (highSev) {
          // Play sound
          const audio = new Audio("/alert.mp3");
          audio.play().catch(() => {});

          // Browser notification
          if (
            "Notification" in window &&
            Notification.permission === "granted"
          ) {
            new Notification(`🚨 SHADOW HUNTER: ${highSev.message}`, {
              body: `Source: ${highSev.source} → Target: ${highSev.target}`,
              icon: "/favicon.ico",
              tag: "shadow-hunter-alert",
            });
          }
        }
      }
      setAlertCount(alertsData.length);
      lastAlertCountRef.current = alertsData.length;
    } catch (e) {
      console.error("Failed to fetch stats:", e);
    }
  };

  // WebSocket Connection
  useEffect(() => {
    // Initial fetch
    fetchStats();

    let ws = null;
    let reconnectTimeout = null;

    const connect = () => {
      ws = new WebSocket("ws://localhost:8000/ws");

      ws.onopen = () => {
        console.log("🟢 Connected to Real-Time Intelligence Feed");
      };

      ws.onmessage = (event) => {
        const msg = JSON.parse(event.data);
        if (msg.type === "alert") {
          console.log("⚡ Real-time alert received");
          fetchStats(); // Instant refresh
        }
      };

      ws.onerror = (e) => {
        console.error("WS Error:", e);
      };

      ws.onclose = () => {
        console.log("🔴 Disconnected from Real-Time Feed. Reconnecting...");
        ws = null;
        reconnectTimeout = setTimeout(connect, 3000); // Try reconnecting in 3s
      };
    };

    connect();

    // Fallback polling (slower now, since we have WS)
    const interval = setInterval(fetchStats, 10000);

    return () => {
      clearInterval(interval);
      if (reconnectTimeout) clearTimeout(reconnectTimeout);
      if (ws) ws.close();
    };
  }, []);

  return (
    <div className="h-screen w-screen bg-sh-bg text-slate-200 font-sans flex overflow-hidden selection:bg-red-500/30">
      {/* 1. Sidebar */}
      <aside className="w-16 flex-none bg-sh-panel border-r border-sh-border flex flex-col items-center py-4 gap-6 z-30">
        <div className="w-10 h-10 bg-red-500/10 rounded-xl border border-red-500/20 flex items-center justify-center text-red-500 shadow-[0_0_15px_rgba(239,68,68,0.2)]">
          <Shield className="w-6 h-6" />
        </div>

        <nav className="flex flex-col gap-4 w-full px-2">
          <NavItem
            icon={<LayoutDashboard />}
            active={activeTab === "dashboard"}
            onClick={() => setActiveTab("dashboard")}
            tooltip="Dashboard"
          />
          <NavItem
            icon={<Network />}
            active={activeTab === "network"}
            onClick={() => setActiveTab("network")}
            tooltip="Network"
          />
          <NavItem
            icon={<Bell />}
            active={activeTab === "alerts"}
            badge={alertCount > 0 ? alertCount : null}
            onClick={() => setActiveTab("alerts")}
            tooltip="Alerts"
          />
          <NavItem
            icon={<Settings />}
            active={activeTab === "settings"}
            onClick={() => setActiveTab("settings")}
            tooltip="Settings"
          />
          <NavItem
            icon={<Clock />}
            active={activeTab === "timeline"}
            onClick={() => setActiveTab("timeline")}
            tooltip="Timeline"
          />
          <NavItem
            icon={<Eye />}
            active={activeTab === "profiles"}
            onClick={() => setActiveTab("profiles")}
            tooltip="User Profiles"
          />
          <NavItem
            icon={<Layers />}
            active={activeTab === "sessions"}
            onClick={() => setActiveTab("sessions")}
            tooltip="Sessions"
          />
          <NavItem
            icon={<ShieldAlert />}
            active={activeTab === "dlp"}
            onClick={() => setActiveTab("dlp")}
            tooltip="DLP Monitor"
          />
          <NavItem
            icon={<Activity />}
            active={activeTab === "killchain"}
            onClick={() => setActiveTab("killchain")}
            tooltip="Kill Chain"
          />
          <NavItem
            icon={<CheckSquare />}
            active={activeTab === "compliance"}
            onClick={() => setActiveTab("compliance")}
            tooltip="Compliance"
          />
        </nav>

        <div className="mt-auto flex flex-col gap-4">
          <div className="w-2 h-2 bg-green-500 rounded-full animate-pulse shadow-[0_0_8px_#22c55e]"></div>
        </div>
      </aside>

      {/* 2. Main Layout */}
      <div className="flex-1 flex flex-col min-w-0">
        {/* Header */}
        <header className="h-14 flex-none border-b border-sh-border flex items-center justify-between px-6 bg-sh-bg/80 backdrop-blur-sm z-20">
          <div className="flex items-center gap-4">
            <h1 className="text-lg font-bold tracking-widest text-white font-mono">
              SHADOW<span className="text-red-500">HUNTER</span>
              <span className="text-[10px] ml-2 text-slate-500 px-1.5 py-0.5 border border-slate-700 rounded bg-slate-900">
                v2.0
              </span>
            </h1>
            <div className="hidden md:flex items-center gap-2 text-[10px] text-slate-500 uppercase tracking-widest font-semibold ml-4 border-l border-slate-800 pl-4">
              <span
                className={`w-1.5 h-1.5 rounded-full ${isLiveMode ? "bg-green-500 animate-pulse shadow-[0_0_8px_#22c55e]" : "bg-amber-500 animate-pulse"}`}
              ></span>
              {isLiveMode ? "LIVE MODE" : "DEMO MODE"}
            </div>
          </div>

          <div className="flex items-center gap-6">
            <div className="relative hidden md:block group">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500 group-focus-within:text-blue-400 transition-colors" />
              <input
                type="text"
                placeholder="SEARCH..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="bg-sh-panel border border-sh-border rounded-full py-1.5 pl-9 pr-4 text-xs font-mono w-56 focus:outline-none focus:border-blue-500/50 focus:ring-1 focus:ring-blue-500/20 transition-all text-slate-300 placeholder:text-slate-600"
              />
            </div>
            <div className="text-right border-l border-sh-border pl-6 flex items-center gap-4">
              {/* Theme Toggle */}
              <button
                onClick={toggleTheme}
                className={`theme-toggle ${darkMode ? "dark" : "light"}`}
                title={
                  darkMode ? "Switch to Light Mode" : "Switch to Dark Mode"
                }
              >
                <div className="theme-toggle-knob">
                  {darkMode ? "🌙" : "☀️"}
                </div>
              </button>
              <div>
                <div className="text-xl font-mono font-light leading-none tracking-tight text-slate-300">
                  {time.toLocaleTimeString([], { hour12: false })}
                </div>
                <div className="text-[9px] text-slate-500 font-bold tracking-widest uppercase">
                  UTC / ZULU
                </div>
              </div>
            </div>
          </div>
        </header>

        {/* Content */}
        <main className="flex-1 overflow-hidden relative">
          {/* Background Grid */}
          <div className="absolute inset-0 bg-[linear-gradient(to_right,#1e293b_1px,transparent_1px),linear-gradient(to_bottom,#1e293b_1px,transparent_1px)] bg-size-[40px_40px] opacity-[0.04] pointer-events-none"></div>

          {/* Dashboard Tab */}
          {activeTab === "dashboard" && (
            <div className="h-full flex flex-col p-2 gap-2">
              {/* Top Stats Row */}
              <div className="flex gap-2 flex-none">
                <StatCard
                  className="flex-1"
                  label="TOTAL NODES"
                  value={stats.nodes}
                  icon={<Monitor className="text-blue-400" />}
                />
                <StatCard
                  className="flex-1"
                  label="INTERNAL"
                  value={nodeList.filter((n) => n.type === "internal").length}
                  icon={<Server className="text-sky-400" />}
                  borderColor="border-sky-500/20"
                />
                <StatCard
                  className="flex-1"
                  label="EXTERNAL"
                  value={nodeList.filter((n) => n.type === "external").length}
                  icon={<Globe className="text-emerald-400" />}
                  borderColor="border-emerald-500/20"
                />
                <StatCard
                  className="flex-1"
                  label="THREATS"
                  value={stats.shadowCount}
                  icon={<AlertTriangle className="text-red-400" />}
                  borderColor="border-red-500/30"
                />
                <StatCard
                  className="flex-1"
                  label="CONNECTIONS"
                  value={stats.edges}
                  icon={<Activity className="text-cyan-400" />}
                />
              </div>

              <div className="flex-1 flex gap-2 min-h-0">
                {/* Graph */}
                <div className="flex-1 h-full min-w-0 relative bg-sh-panel/30 border border-sh-border rounded-xl overflow-hidden">
                  <div className="absolute top-0 left-0 w-6 h-6 border-l-2 border-t-2 border-slate-700/50 rounded-tl-lg pointer-events-none"></div>
                  <div className="absolute bottom-0 right-0 w-6 h-6 border-r-2 border-b-2 border-slate-700/50 rounded-br-lg pointer-events-none"></div>
                  <GraphView />
                </div>
                {/* Alerts Panel */}
                <div className="w-[360px] flex-none flex flex-col gap-2">
                  <Alerts
                    onNavigateToNode={(nodeId) => {
                      setSearchQuery(nodeId);
                    }}
                  />
                </div>
              </div>
              {/* Bottom Row: Top Offenders */}
              {riskScores.length > 0 && (
                <div className="h-[100px] flex-none bg-sh-panel border border-sh-border rounded-xl overflow-hidden">
                  <div className="flex items-center justify-between px-4 py-1.5 border-b border-sh-border bg-slate-900/50">
                    <div className="flex items-center gap-2 text-[10px] font-mono font-bold text-slate-400 uppercase tracking-widest">
                      <TrendingUp size={12} className="text-amber-400" />
                      Top Offenders
                    </div>
                    <span className="text-[9px] font-mono text-slate-600">
                      Risk Score
                    </span>
                  </div>
                  <div className="flex gap-0 h-[calc(100%-29px)] divide-x divide-sh-border/50 overflow-x-auto custom-scrollbar">
                    {riskScores.slice(0, 6).map((r, i) => (
                      <div
                        key={r.ip}
                        className="flex-1 min-w-[140px] flex flex-col items-center justify-center p-1.5 hover:bg-slate-800/30 transition-colors"
                      >
                        <div className="flex items-center gap-1.5 mb-0.5">
                          <span
                            className={`text-xs font-mono font-bold ${
                              i === 0
                                ? "text-red-400"
                                : i === 1
                                  ? "text-amber-400"
                                  : "text-slate-300"
                            }`}
                          >
                            #{i + 1}
                          </span>
                        </div>
                        <div
                          className="text-[10px] font-mono text-slate-300 truncate max-w-[120px]"
                          title={r.ip}
                        >
                          {r.ip}
                        </div>
                        <div className="w-full mt-1 bg-slate-800 rounded-full h-1">
                          <div
                            className={`h-1 rounded-full transition-all ${
                              r.risk_pct > 70
                                ? "bg-red-500"
                                : r.risk_pct > 40
                                  ? "bg-amber-500"
                                  : "bg-blue-500"
                            }`}
                            style={{ width: `${r.risk_pct}%` }}
                          />
                        </div>
                        <div className="flex items-center gap-2 mt-0.5">
                          <span className="text-[8px] font-mono text-slate-500">
                            {r.total_alerts} alerts
                          </span>
                          <span
                            className={`text-[8px] font-mono font-bold ${
                              r.risk_pct > 70
                                ? "text-red-400"
                                : r.risk_pct > 40
                                  ? "text-amber-400"
                                  : "text-blue-400"
                            }`}
                          >
                            {r.risk_pct}%
                          </span>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Network Tab */}
          {activeTab === "network" && (
            <NetworkTabView
              nodes={nodeList}
              stats={stats}
              searchQuery={searchQuery}
              onExport={() =>
                downloadCSV(
                  nodeList,
                  `shadow_hunter_nodes_${new Date().toISOString().split("T")[0]}.csv`,
                )
              }
            />
          )}

          {/* Alerts Tab */}
          {activeTab === "alerts" && (
            <div className="h-full p-3">
              <Alerts
                searchQuery={searchQuery}
                onExport={(data) =>
                  downloadCSV(
                    data,
                    `shadow_hunter_alerts_${new Date().toISOString().split("T")[0]}.csv`,
                  )
                }
                onNavigateToNode={(nodeId) => {
                  setActiveTab("dashboard");
                  setSearchQuery(nodeId);
                }}
              />
            </div>
          )}

          {/* Timeline Tab */}
          {activeTab === "timeline" && (
            <div className="h-full p-3">
              <Timeline searchQuery={searchQuery} />
            </div>
          )}

          {/* User Profiles Tab */}
          {activeTab === "profiles" && (
            <div className="h-full p-3">
              <UserProfiles
                searchQuery={searchQuery}
                onNavigateToNode={(nodeId) => {
                  setActiveTab("dashboard");
                  setSearchQuery(nodeId);
                }}
              />
            </div>
          )}

          {/* Sessions Tab */}
          {activeTab === "sessions" && (
            <div className="h-full p-3">
              <SessionTracking
                searchQuery={searchQuery}
                onNavigateToNode={(nodeId) => {
                  setActiveTab("dashboard");
                  setSearchQuery(nodeId);
                }}
              />
            </div>
          )}

          {/* DLP Monitor Tab */}
          {activeTab === "dlp" && (
            <div className="h-full p-3">
              <DlpMonitor searchQuery={searchQuery} />
            </div>
          )}

          {/* Kill Chain Tab */}
          {activeTab === "killchain" && (
            <div className="h-full p-3">
              <KillChain />
            </div>
          )}

          {/* Compliance Tab */}
          {activeTab === "compliance" && (
            <div className="h-full p-3">
              <ComplianceBoard />
            </div>
          )}

          {/* Settings Tab */}
          {activeTab === "settings" && <SettingsView />}
        </main>
      </div>
    </div>
  );
}

// ═══════════════════════════════════════════════════════
// Network Tab — Sub-tab switcher (Nodes / Analytics)
// ═══════════════════════════════════════════════════════
const NetworkTabView = ({ nodes, stats, searchQuery, onExport }) => {
  const [subTab, setSubTab] = useState("nodes");

  return (
    <div className="h-full flex flex-col">
      {/* Sub-tab bar */}
      <div className="flex items-center gap-1 px-3 pt-2 pb-0">
        {[
          { key: "nodes", label: "Node Inventory", icon: <Server size={13} /> },
          {
            key: "analytics",
            label: "Traffic Analytics",
            icon: <BarChart2 size={13} />,
          },
        ].map((tab) => (
          <button
            key={tab.key}
            onClick={() => setSubTab(tab.key)}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-t-lg text-[11px] font-mono font-semibold uppercase tracking-wider transition-all ${
              subTab === tab.key
                ? "bg-sh-panel text-blue-400 border border-sh-border border-b-transparent"
                : "text-slate-500 hover:text-slate-300"
            }`}
          >
            {tab.icon}
            {tab.label}
          </button>
        ))}
      </div>

      {/* Sub-tab content */}
      <div className="flex-1 min-h-0">
        {subTab === "nodes" && (
          <NetworkView
            nodes={nodes}
            stats={stats}
            searchQuery={searchQuery}
            onExport={onExport}
          />
        )}
        {subTab === "analytics" && <TrafficAnalytics />}
      </div>
    </div>
  );
};

// ═══════════════════════════════════════════════════════
// Network View — Full-screen node inventory
// ═══════════════════════════════════════════════════════
const NetworkView = ({ nodes, stats, searchQuery, onExport }) => {
  const [filter, setFilter] = useState("all");
  const filtered = nodes.filter((n) => {
    const matchesType = filter === "all" || n.type === filter;
    const matchesSearch =
      !searchQuery ||
      n.id.toLowerCase().includes(searchQuery.toLowerCase()) ||
      (n.label && n.label.toLowerCase().includes(searchQuery.toLowerCase()));
    return matchesType && matchesSearch;
  });

  return (
    <div className="h-full flex flex-col p-3 gap-3">
      {/* Stats Bar */}
      <div className="flex gap-3">
        <MiniStat
          icon={<Server />}
          label="Total Nodes"
          value={stats.nodes}
          color="text-blue-400"
        />
        <MiniStat
          icon={<Monitor />}
          label="Internal"
          value={nodes.filter((n) => n.type === "internal").length}
          color="text-sky-400"
        />
        <MiniStat
          icon={<Globe />}
          label="External"
          value={nodes.filter((n) => n.type === "external").length}
          color="text-emerald-400"
        />
        <MiniStat
          icon={<AlertTriangle />}
          label="Shadow AI"
          value={nodes.filter((n) => n.type === "shadow").length}
          color="text-red-400"
        />
        <MiniStat
          icon={<Wifi />}
          label="Connections"
          value={stats.edges}
          color="text-cyan-400"
        />
      </div>

      {/* Filter Bar */}
      <div className="flex gap-2 justify-between">
        <div className="flex gap-2">
          {["all", "internal", "external", "shadow"].map((f) => (
            <button
              key={f}
              onClick={() => setFilter(f)}
              className={`px-3 py-1.5 rounded-lg text-[11px] font-mono font-semibold uppercase tracking-wider transition-all ${
                filter === f
                  ? f === "shadow"
                    ? "bg-red-500/20 text-red-400 border border-red-500/30"
                    : "bg-blue-500/20 text-blue-400 border border-blue-500/30"
                  : "bg-sh-panel text-slate-500 border border-sh-border hover:text-slate-300 hover:border-slate-600"
              }`}
            >
              {f === "all" ? "All Nodes" : f}
            </button>
          ))}
        </div>
        <button
          onClick={onExport}
          className="px-3 py-1.5 rounded-lg text-[11px] font-mono font-semibold uppercase tracking-wider bg-sh-panel text-slate-400 border border-sh-border hover:text-white hover:border-slate-500 flex items-center gap-2 transition-all"
        >
          <Download size={12} />
          Export CSV
        </button>
      </div>

      {/* Table */}
      <div className="flex-1 bg-sh-panel border border-sh-border rounded-xl overflow-hidden">
        <div className="grid grid-cols-[50px_1fr_120px_200px] gap-0 text-[10px] font-mono uppercase tracking-widest text-slate-500 border-b border-sh-border bg-slate-900/50 px-4 py-2.5">
          <span>#</span>
          <span>Node ID</span>
          <span>Type</span>
          <span>Last Seen</span>
        </div>
        <div className="overflow-y-auto h-[calc(100%-40px)] custom-scrollbar">
          {filtered.length === 0 ? (
            <div className="flex items-center justify-center h-32 text-slate-600 text-sm font-mono">
              No nodes discovered yet...
            </div>
          ) : (
            filtered.map((node, i) => (
              <div
                key={node.id}
                className="grid grid-cols-[50px_1fr_120px_200px] gap-0 px-4 py-2.5 border-b border-sh-border/50 hover:bg-slate-800/40 transition-colors text-sm items-center"
              >
                <span className="text-slate-600 text-xs font-mono">
                  {i + 1}
                </span>
                <span className="font-mono text-slate-200 truncate pr-4">
                  {node.label || node.id}
                </span>
                <TypeBadge type={node.type} />
                <span className="text-slate-500 text-xs font-mono">
                  {node.last_seen
                    ? new Date(node.last_seen).toLocaleTimeString([], {
                        hour12: false,
                      })
                    : "—"}
                </span>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
};

// ═══════════════════════════════════════════════════════
// Settings View
// ═══════════════════════════════════════════════════════
const SettingsView = () => {
  const [generating, setGenerating] = useState(false);

  const handleGenerateReport = async (format = "pdf") => {
    setGenerating(true);
    try {
      const report = await fetchReport();
      if (report) {
        if (format === "pdf") {
          generatePdfReport(report);
        } else {
          const blob = new Blob([JSON.stringify(report, null, 2)], {
            type: "application/json",
          });
          const url = URL.createObjectURL(blob);
          const a = document.createElement("a");
          a.href = url;
          a.download = `shadow_hunter_report_${new Date().toISOString().slice(0, 10)}.json`;
          a.click();
          URL.revokeObjectURL(url);
        }
      }
    } catch (e) {
      console.error("Report generation failed:", e);
    }
    setGenerating(false);
  };

  return (
    <div className="h-full p-4 overflow-y-auto">
      <div className="max-w-2xl mx-auto space-y-4">
        <h2 className="text-xl font-mono font-bold text-slate-200 flex items-center gap-2 mb-6">
          <Settings className="w-5 h-5 text-slate-400" /> SYSTEM_CONFIG
        </h2>

        <SettingsGroup title="Detection Engine">
          <SettingRow
            label="Shadow AI Detection"
            description="Flag traffic to known AI services"
            defaultOn={true}
          />
          <SettingRow
            label="Anomalous Port Detection"
            description="Alert on non-standard outbound ports"
            defaultOn={true}
          />
          <SettingRow
            label="DNS Tunneling Detection"
            description="Detect large DNS payloads"
            defaultOn={true}
          />
          <SettingRow
            label="ML Intelligence Engine"
            description="Enhanced detection via trained ML models"
            defaultOn={true}
          />
        </SettingsGroup>

        <SettingsGroup title="Traffic Capture">
          <SettingRow
            label="Demo Mode"
            description="Simulate corporate traffic for demonstration"
            defaultOn={true}
          />
          <SettingRow
            label="Live Packet Capture"
            description="Real-time network analysis via Npcap"
            defaultOn={false}
          />
        </SettingsGroup>

        <SettingsGroup title="Dashboard">
          <SettingRow
            label="Auto-refresh Interval"
            description="Fetch new data every 5 seconds"
            defaultOn={true}
          />
          <SettingRow
            label="Sound Alerts"
            description="Play audio on HIGH severity alerts"
            defaultOn={false}
          />
        </SettingsGroup>

        {/* Generate Report */}
        <div className="bg-sh-panel border border-sh-border rounded-xl overflow-hidden">
          <div className="px-4 py-2.5 border-b border-sh-border bg-slate-900/50 text-xs font-mono font-bold text-slate-400 uppercase tracking-widest">
            Report
          </div>
          <div className="p-4">
            <p className="text-xs text-slate-500 mb-3">
              Generate a styled PDF report with executive summary, severity
              charts, top offenders, and recommendations.
            </p>
            <div className="flex gap-2">
              <button
                onClick={() => handleGenerateReport("pdf")}
                disabled={generating}
                className="flex items-center gap-2 px-4 py-2 bg-red-500/10 text-red-400 border border-red-500/30 rounded-lg text-xs font-mono font-bold uppercase tracking-wider hover:bg-red-500/20 transition-all disabled:opacity-50"
              >
                <Download size={14} />
                {generating ? "Generating…" : "Download PDF"}
              </button>
              <button
                onClick={() => handleGenerateReport("json")}
                disabled={generating}
                className="flex items-center gap-2 px-4 py-2 bg-blue-500/10 text-blue-400 border border-blue-500/30 rounded-lg text-xs font-mono font-bold uppercase tracking-wider hover:bg-blue-500/20 transition-all disabled:opacity-50"
              >
                <Download size={14} />
                JSON
              </button>
            </div>
          </div>
        </div>

        {/* Policy Engine */}
        <PolicyEngine />

        {/* Executive Briefing */}
        <div className="mt-6">
          <ExecutiveBriefing />
        </div>

        <div className="mt-8 p-4 bg-slate-900/50 border border-sh-border rounded-xl">
          <div className="text-[10px] font-mono text-slate-500 uppercase tracking-widest mb-2">
            System Info
          </div>
          <div className="space-y-1 text-xs font-mono text-slate-400">
            <div className="flex justify-between">
              <span className="text-slate-500">Version</span>
              <span>2.0.0-ml</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-500">Mode</span>
              <span className="text-green-400">HYBRID (Rules + ML)</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-500">Backend</span>
              <span>localhost:8000</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-500">Npcap</span>
              <span className="text-green-400">Installed ✓</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-500">ML Models</span>
              <span className="text-green-400">Loaded ✓</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

// ═══════════════════════════════════════════════════════
// Sub-components
// ═══════════════════════════════════════════════════════

const NavItem = ({ icon, active, badge, onClick, tooltip }) => (
  <button
    onClick={onClick}
    title={tooltip}
    className={`w-full aspect-square flex items-center justify-center rounded-xl transition-all relative ${
      active
        ? "bg-blue-500/10 text-blue-400 border border-blue-500/20 shadow-[0_0_10px_rgba(59,130,246,0.1)]"
        : "text-slate-500 hover:bg-slate-800 hover:text-slate-300"
    }`}
  >
    {React.cloneElement(icon, { size: 20 })}
    {badge && (
      <span className="absolute -top-0.5 -right-0.5 min-w-[16px] h-4 flex items-center justify-center bg-red-500 rounded-full text-[9px] font-bold text-white px-1 border-2 border-sh-panel">
        {badge > 9 ? "9+" : badge}
      </span>
    )}
  </button>
);

const StatCard = ({
  label,
  value,
  icon,
  borderColor = "border-sh-border",
  className = "",
}) => (
  <div
    className={`bg-sh-panel/50 backdrop-blur-md border ${borderColor} rounded-xl px-4 py-2 flex items-center gap-3 shadow-lg min-w-[140px] transition-all hover:scale-105 hover:bg-sh-panel/80 ${className}`}
  >
    <div className="p-2 bg-slate-800/50 rounded-lg">
      {React.cloneElement(icon, { size: 18 })}
    </div>
    <div>
      <div className="text-[10px] font-mono font-bold text-slate-500 tracking-wider">
        {label}
      </div>
      <div className="text-xl font-mono font-bold text-slate-200 leading-none">
        {value}
      </div>
    </div>
  </div>
);

const MiniStat = ({ icon, label, value, color }) => (
  <div className="flex-1 bg-sh-panel border border-sh-border rounded-xl p-3 flex items-center gap-3">
    <div className={`${color}`}>{React.cloneElement(icon, { size: 18 })}</div>
    <div>
      <div className="text-[10px] text-slate-500 font-bold tracking-wider uppercase">
        {label}
      </div>
      <div className="text-lg font-mono font-bold text-slate-200">{value}</div>
    </div>
  </div>
);

const TypeBadge = ({ type }) => {
  const styles = {
    internal: "bg-sky-500/10 text-sky-400 border-sky-500/30",
    external: "bg-emerald-500/10 text-emerald-400 border-emerald-500/30",
    shadow: "bg-red-500/10 text-red-400 border-red-500/30",
  };
  return (
    <span
      className={`text-[10px] font-mono font-bold uppercase px-2 py-0.5 rounded border ${styles[type] || "text-slate-500 border-slate-700"}`}
    >
      {type || "unknown"}
    </span>
  );
};

const SettingsGroup = ({ title, children }) => (
  <div className="bg-sh-panel border border-sh-border rounded-xl overflow-hidden">
    <div className="px-4 py-2.5 border-b border-sh-border bg-slate-900/50 text-xs font-mono font-bold text-slate-400 uppercase tracking-widest">
      {title}
    </div>
    <div className="divide-y divide-sh-border/50">{children}</div>
  </div>
);

const SettingRow = ({
  label,
  description,
  defaultOn = false,
  disabled = false,
}) => {
  const [on, setOn] = useState(defaultOn);
  return (
    <div
      className={`flex items-center justify-between px-4 py-3 ${disabled ? "opacity-40" : "hover:bg-slate-800/30"} transition-colors`}
    >
      <div>
        <div className="text-sm text-slate-200">{label}</div>
        <div className="text-xs text-slate-500">{description}</div>
      </div>
      <button
        onClick={() => !disabled && setOn(!on)}
        className={`w-10 h-5 rounded-full transition-all relative ${on ? "bg-blue-500" : "bg-slate-700"}`}
      >
        <span
          className={`absolute top-0.5 w-4 h-4 rounded-full bg-white shadow transition-all ${on ? "left-5.5" : "left-0.5"}`}
          style={{ left: on ? "22px" : "2px" }}
        />
      </button>
    </div>
  );
};

export default App;
