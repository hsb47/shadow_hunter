import React, { useEffect, useRef, useState } from "react";
import cytoscape from "cytoscape";
import { fetchGraphData, fetchAlerts } from "./api";
import {
  X,
  Globe,
  Server,
  AlertTriangle,
  Clock,
  Wifi,
  Shield,
} from "lucide-react";

const STYLESHEET = [
  // ─── Base Node ───
  {
    selector: "node",
    style: {
      "background-color": "#1e293b",
      label: "data(label)",
      color: "#94a3b8",
      "font-size": "9px",
      "font-family": "'Courier New', monospace",
      "text-valign": "bottom",
      "text-margin-y": 8,
      width: 36,
      height: 36,
      "border-width": 1.5,
      "border-color": "#334155",
      "overlay-opacity": 0,
      "text-outline-width": 2,
      "text-outline-color": "#0f172a",
      "text-wrap": "ellipsis",
      "text-max-width": "80px",
    },
  },
  // ─── Internal (Blue Squares) ───
  {
    selector: 'node[type="internal"]',
    style: {
      "background-color": "#0c4a6e",
      "border-color": "#0ea5e9",
      "border-width": 2,
      width: 44,
      height: 44,
      shape: "round-rectangle",
      color: "#7dd3fc",
    },
  },
  // ─── Shadow AI (RED Hexagons) ───
  {
    selector: 'node[type="shadow"]',
    style: {
      "background-color": "#450a0a",
      "border-color": "#ef4444",
      "border-width": 2.5,
      shape: "hexagon",
      width: 56,
      height: 56,
      color: "#fca5a5",
      "font-weight": "bold",
      "font-size": "10px",
      "shadow-blur": 15,
      "shadow-color": "#ef4444",
      "shadow-opacity": 0.6,
    },
  },
  // ─── External (Green Circles) ───
  {
    selector: 'node[type="external"]',
    style: {
      "background-color": "#064e3b",
      "border-color": "#10b981",
      "border-width": 1.5,
      width: 36,
      height: 36,
      shape: "ellipse",
      color: "#6ee7b7",
    },
  },
  // ─── Selected node highlight ───
  {
    selector: "node:selected",
    style: {
      "border-width": 3,
      "border-color": "#f59e0b",
      "shadow-blur": 20,
      "shadow-color": "#f59e0b",
      "shadow-opacity": 0.5,
    },
  },
  // ─── Connected edges highlight ───
  {
    selector: "edge.highlighted",
    style: {
      "line-color": "#f59e0b",
      "target-arrow-color": "#f59e0b",
      width: 2.5,
      opacity: 1,
      "z-index": 999,
    },
  },
  // ─── Connected neighbor nodes ───
  {
    selector: "node.neighbor",
    style: {
      "border-color": "#f59e0b",
      "border-width": 2,
    },
  },
  // ─── Edges ───
  {
    selector: "edge",
    style: {
      width: 1.5,
      "line-color": "#1e293b",
      "target-arrow-color": "#334155",
      "target-arrow-shape": "triangle",
      "curve-style": "bezier",
      "arrow-scale": 0.7,
      opacity: 0.5,
    },
  },
  {
    selector: 'edge[protocol="HTTPS"]',
    style: {
      "line-color": "#334155",
      "target-arrow-color": "#475569",
      width: 1.5,
    },
  },
  {
    selector: 'edge[protocol="TCP"]',
    style: {
      "line-color": "#1e3a5f",
      "target-arrow-color": "#1e3a5f",
      width: 1,
    },
  },
  {
    selector: 'edge[protocol="HTTP"]',
    style: {
      "line-color": "#374151",
      "target-arrow-color": "#374151",
      "line-style": "dashed",
      width: 1,
    },
  },
];

const GraphView = () => {
  const containerRef = useRef(null);
  const cyRef = useRef(null);
  const knownNodeIds = useRef(new Set());
  const knownEdgeIds = useRef(new Set());
  const initialLayoutDone = useRef(false);
  const [selectedNode, setSelectedNode] = useState(null);
  const [nodeAlerts, setNodeAlerts] = useState([]);
  const [nodeConnections, setNodeConnections] = useState([]);

  // Initialize Cytoscape once
  useEffect(() => {
    if (!containerRef.current) return;

    const cy = cytoscape({
      container: containerRef.current,
      style: STYLESHEET,
      layout: { name: "preset" },
      minZoom: 0.3,
      maxZoom: 3,
      wheelSensitivity: 0.5,
      textureOnViewport: true,
      hideEdgesOnViewport: true,
      hideLabelsOnViewport: true,
      pixelRatio: 1,
      selectionType: "single",
      boxSelectionEnabled: false,
    });

    // Node click handler
    cy.on("tap", "node", (evt) => {
      const node = evt.target;
      const data = node.data();

      // Clear previous highlights
      cy.elements().removeClass("highlighted neighbor");

      // Highlight connected edges and neighbor nodes
      const connectedEdges = node.connectedEdges();
      const neighbors = node.neighborhood("node");
      connectedEdges.addClass("highlighted");
      neighbors.addClass("neighbor");

      // Get connection details
      const conns = connectedEdges.map((edge) => ({
        source: edge.data("source"),
        target: edge.data("target"),
        protocol: edge.data("protocol"),
        port: edge.data("dst_port"),
        bytes: edge.data("byte_count"),
      }));

      setNodeConnections(conns);
      setSelectedNode(data);

      // Find alerts for this node
      fetchAlerts().then((alerts) => {
        const related = alerts.filter(
          (a) =>
            a.source === data.id ||
            a.target === data.id ||
            a.source === data.label ||
            a.target === data.label,
        );
        setNodeAlerts(related);
      });
    });

    // Click background to deselect
    cy.on("tap", (evt) => {
      if (evt.target === cy) {
        cy.elements().removeClass("highlighted neighbor");
        setSelectedNode(null);
        setNodeAlerts([]);
        setNodeConnections([]);
      }
    });

    cyRef.current = cy;

    return () => {
      cy.destroy();
      cyRef.current = null;
    };
  }, []);

  // Poll for data and incrementally add elements
  useEffect(() => {
    const loadGraph = async () => {
      const { nodes, edges } = await fetchGraphData();
      const cy = cyRef.current;
      if (!cy) return;

      let addedNew = false;

      for (const node of nodes) {
        const id = node.data.id;
        if (!knownNodeIds.current.has(id)) {
          knownNodeIds.current.add(id);
          const w = containerRef.current?.offsetWidth || 800;
          const h = containerRef.current?.offsetHeight || 600;
          cy.add({
            group: "nodes",
            data: node.data,
            position: {
              x: 100 + Math.random() * (w - 200),
              y: 100 + Math.random() * (h - 200),
            },
          });
          addedNew = true;
        } else {
          const existing = cy.getElementById(id);
          if (existing.length) {
            existing.data(node.data);
          }
        }
      }

      for (const edge of edges) {
        const id = edge.data.id;
        if (!knownEdgeIds.current.has(id)) {
          knownEdgeIds.current.add(id);
          if (
            cy.getElementById(edge.data.source).length &&
            cy.getElementById(edge.data.target).length
          ) {
            cy.add({ group: "edges", data: edge.data });
          }
        }
      }

      if (!initialLayoutDone.current && nodes.length > 3) {
        initialLayoutDone.current = true;
        const ly = cy.layout({
          name: "cose",
          animate: true,
          animationDuration: 800,
          nodeDimensionsIncludeLabels: true,
          padding: 60,
          nodeRepulsion: () => 8000,
          idealEdgeLength: () => 130,
          edgeElasticity: () => 100,
          gravity: 0.25,
          numIter: 300,
          randomize: false,
          componentSpacing: 100,
        });
        ly.run();
      }
    };

    loadGraph();
    const interval = setInterval(loadGraph, 5000);
    return () => clearInterval(interval);
  }, []);

  const typeConfig = {
    internal: {
      color: "text-sky-400",
      bg: "bg-sky-500/10",
      border: "border-sky-500/30",
      icon: <Server size={14} />,
    },
    external: {
      color: "text-emerald-400",
      bg: "bg-emerald-500/10",
      border: "border-emerald-500/30",
      icon: <Globe size={14} />,
    },
    shadow: {
      color: "text-red-400",
      bg: "bg-red-500/10",
      border: "border-red-500/30",
      icon: <AlertTriangle size={14} />,
    },
  };

  return (
    <div className="w-full h-full relative">
      {/* Graph Label */}
      <div className="absolute top-2 left-2 z-10 text-[10px] font-mono text-slate-600 flex items-center gap-2">
        NETWORK_TOPOLOGY
        <span className="w-1.5 h-1.5 bg-green-500 rounded-full animate-pulse"></span>
        <span className="text-green-500/50">LIVE</span>
      </div>

      {/* Legend */}
      <div className="absolute bottom-3 left-3 z-10 flex gap-3 text-[9px] font-mono text-slate-500 bg-sh-bg/70 px-2 py-1 rounded backdrop-blur-sm">
        <div className="flex items-center gap-1">
          <span className="w-3 h-3 rounded-sm bg-sky-700 border border-sky-500 inline-block"></span>
          Internal
        </div>
        <div className="flex items-center gap-1">
          <span className="w-3 h-3 rounded-full bg-emerald-900 border border-emerald-500 inline-block"></span>
          External
        </div>
        <div className="flex items-center gap-1">
          <span
            className="w-3 h-3 bg-red-950 border-2 border-red-500 inline-block"
            style={{
              clipPath:
                "polygon(50% 0%, 100% 25%, 100% 75%, 50% 100%, 0% 75%, 0% 25%)",
            }}
          ></span>
          Shadow AI
        </div>
      </div>

      {/* Cytoscape Container */}
      <div ref={containerRef} style={{ width: "100%", height: "100%" }} />

      {/* ═══ Node Detail Slide-Out Panel ═══ */}
      {selectedNode && (
        <div className="absolute top-0 right-0 h-full w-[320px] bg-sh-bg/95 backdrop-blur-xl border-l border-sh-border z-20 flex flex-col animate-in slide-in-from-right duration-200 shadow-2xl">
          {/* Header */}
          <div className="flex items-center justify-between p-4 border-b border-sh-border">
            <div className="flex items-center gap-2">
              <div
                className={`p-1.5 rounded-lg ${typeConfig[selectedNode.type]?.bg || "bg-slate-800"} ${typeConfig[selectedNode.type]?.border || "border-slate-700"} border`}
              >
                {typeConfig[selectedNode.type]?.icon || (
                  <Globe size={14} className="text-slate-400" />
                )}
              </div>
              <div>
                <div className="text-[10px] font-mono text-slate-500 uppercase tracking-wider">
                  Node Detail
                </div>
                <div
                  className={`text-xs font-bold ${typeConfig[selectedNode.type]?.color || "text-slate-300"}`}
                >
                  {selectedNode.type?.toUpperCase() || "UNKNOWN"}
                </div>
              </div>
            </div>
            <button
              onClick={() => {
                setSelectedNode(null);
                setNodeAlerts([]);
                setNodeConnections([]);
                cyRef.current?.elements().removeClass("highlighted neighbor");
              }}
              className="p-1 rounded-lg hover:bg-slate-800 text-slate-500 hover:text-slate-300 transition-colors"
            >
              <X size={16} />
            </button>
          </div>

          {/* Body */}
          <div className="flex-1 overflow-y-auto p-4 space-y-4 custom-scrollbar">
            {/* Identity */}
            <div className="space-y-2">
              <SectionLabel>Identity</SectionLabel>
              <DetailRow label="ID" value={selectedNode.id} />
              <DetailRow label="Label" value={selectedNode.label} />
              <DetailRow label="Type" value={selectedNode.type} />
              <DetailRow
                label="Last Seen"
                value={
                  selectedNode.last_seen
                    ? new Date(selectedNode.last_seen).toLocaleTimeString([], {
                        hour12: false,
                      })
                    : "—"
                }
              />
            </div>

            {/* Connections */}
            <div className="space-y-2">
              <SectionLabel>
                <Wifi size={12} className="inline mr-1" />
                Connections ({nodeConnections.length})
              </SectionLabel>
              {nodeConnections.length === 0 ? (
                <div className="text-xs text-slate-600 font-mono">
                  No connections
                </div>
              ) : (
                <div className="space-y-1 max-h-40 overflow-y-auto custom-scrollbar">
                  {nodeConnections.map((c, i) => (
                    <div
                      key={i}
                      className="flex items-center gap-2 text-[11px] font-mono bg-slate-900/50 border border-sh-border/50 rounded-lg px-2.5 py-1.5"
                    >
                      <span className="text-slate-400 truncate flex-1">
                        {c.source === selectedNode.id ? c.target : c.source}
                      </span>
                      <span className="text-slate-600 text-[9px]">
                        {c.protocol}
                      </span>
                      {c.port && (
                        <span className="text-slate-600 text-[9px]">
                          :{c.port}
                        </span>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Alerts */}
            <div className="space-y-2">
              <SectionLabel>
                <Shield size={12} className="inline mr-1" />
                Alerts ({nodeAlerts.length})
              </SectionLabel>
              {nodeAlerts.length === 0 ? (
                <div className="text-xs text-slate-600 font-mono">
                  No alerts for this node
                </div>
              ) : (
                <div className="space-y-1.5 max-h-52 overflow-y-auto custom-scrollbar">
                  {nodeAlerts.slice(0, 10).map((a, i) => (
                    <div
                      key={i}
                      className="bg-slate-900/50 border border-sh-border/50 rounded-lg p-2.5"
                    >
                      <div className="flex items-center gap-2 mb-1">
                        <span
                          className={`text-[9px] font-mono font-bold px-1.5 py-0.5 rounded ${
                            a.severity === "HIGH"
                              ? "bg-red-500/20 text-red-400"
                              : a.severity === "MEDIUM"
                                ? "bg-amber-500/20 text-amber-400"
                                : "bg-blue-500/20 text-blue-400"
                          }`}
                        >
                          {a.severity}
                        </span>
                        <span className="text-[9px] text-slate-600 font-mono">
                          {new Date(a.timestamp).toLocaleTimeString([], {
                            hour12: false,
                          })}
                        </span>
                      </div>
                      <div className="text-[11px] text-slate-400 font-mono leading-tight">
                        {a.description}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

// Small helpers
const SectionLabel = ({ children }) => (
  <div className="text-[10px] font-mono font-bold text-slate-500 uppercase tracking-widest flex items-center gap-1">
    {children}
  </div>
);

const DetailRow = ({ label, value }) => (
  <div className="flex justify-between items-center text-xs font-mono bg-slate-900/30 rounded-lg px-2.5 py-1.5 border border-sh-border/30">
    <span className="text-slate-500">{label}</span>
    <span className="text-slate-300 truncate ml-4 max-w-[180px] text-right">
      {value || "—"}
    </span>
  </div>
);

export default GraphView;
