import React, { useState, useEffect } from "react";
import { fetchRules, createRule, toggleRule, deleteRule } from "./api";
import {
  ShieldCheck,
  Plus,
  Trash2,
  ToggleLeft,
  ToggleRight,
  Shield,
  Eye,
  Ban,
  X,
} from "lucide-react";

const ACTION_STYLES = {
  block: {
    bg: "bg-red-500/10",
    text: "text-red-400",
    border: "border-red-500/30",
    icon: <Ban size={12} />,
    label: "BLOCK",
  },
  allow: {
    bg: "bg-emerald-500/10",
    text: "text-emerald-400",
    border: "border-emerald-500/30",
    icon: <ShieldCheck size={12} />,
    label: "ALLOW",
  },
  monitor: {
    bg: "bg-amber-500/10",
    text: "text-amber-400",
    border: "border-amber-500/30",
    icon: <Eye size={12} />,
    label: "MONITOR",
  },
};

const PolicyEngine = () => {
  const [rules, setRules] = useState([]);
  const [showForm, setShowForm] = useState(false);
  const [form, setForm] = useState({
    name: "",
    action: "monitor",
    service: "",
    department: "All",
    severity: "MEDIUM",
    description: "",
  });

  const loadRules = async () => {
    const data = await fetchRules();
    if (data) setRules(data);
  };

  useEffect(() => {
    loadRules();
  }, []);

  const handleCreate = async () => {
    if (!form.name || !form.service) return;
    const result = await createRule({ ...form, enabled: true });
    if (result) {
      setRules((prev) => [...prev, result]);
      setForm({
        name: "",
        action: "monitor",
        service: "",
        department: "All",
        severity: "MEDIUM",
        description: "",
      });
      setShowForm(false);
    }
  };

  const handleToggle = async (id) => {
    const result = await toggleRule(id);
    if (result && !result.error) {
      setRules((prev) => prev.map((r) => (r.id === id ? result : r)));
    }
    // Fallback: reload
    loadRules();
  };

  const handleDelete = async (id) => {
    await deleteRule(id);
    setRules((prev) => prev.filter((r) => r.id !== id));
  };

  const enabledCount = rules.filter((r) => r.enabled).length;
  const blockCount = rules.filter(
    (r) => r.action === "block" && r.enabled,
  ).length;

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Shield size={14} className="text-emerald-400" />
          <span className="text-xs font-mono font-bold text-slate-300 uppercase tracking-widest">
            Policy Rules
          </span>
          <span className="text-[10px] font-mono text-slate-600 bg-slate-800 px-1.5 py-0.5 rounded-full border border-slate-700">
            {enabledCount} active • {blockCount} blocking
          </span>
        </div>
        <button
          onClick={() => setShowForm(!showForm)}
          className="flex items-center gap-1 text-[10px] font-mono font-bold text-emerald-400 bg-emerald-500/10 hover:bg-emerald-500/20 border border-emerald-500/30 rounded-lg px-2.5 py-1 transition-all"
        >
          {showForm ? <X size={10} /> : <Plus size={10} />}
          {showForm ? "Cancel" : "Add Rule"}
        </button>
      </div>

      {/* Add Rule Form */}
      {showForm && (
        <div className="bg-slate-900/50 border border-emerald-500/20 rounded-xl p-3 space-y-2.5">
          <div className="grid grid-cols-2 gap-2">
            <FormField
              label="Rule Name"
              value={form.name}
              onChange={(v) => setForm({ ...form, name: v })}
              placeholder="e.g. Block ChatGPT for HR"
            />
            <FormField
              label="Target Service"
              value={form.service}
              onChange={(v) => setForm({ ...form, service: v })}
              placeholder="e.g. chatgpt, copilot, claude"
            />
          </div>
          <div className="grid grid-cols-3 gap-2">
            <div>
              <label className="text-[8px] font-mono text-slate-500 uppercase tracking-wider block mb-1">
                Action
              </label>
              <select
                value={form.action}
                onChange={(e) => setForm({ ...form, action: e.target.value })}
                className="w-full bg-slate-800 border border-sh-border rounded px-2 py-1 text-[10px] font-mono text-slate-300 outline-none"
              >
                <option value="block">Block</option>
                <option value="allow">Allow</option>
                <option value="monitor">Monitor</option>
              </select>
            </div>
            <div>
              <label className="text-[8px] font-mono text-slate-500 uppercase tracking-wider block mb-1">
                Department
              </label>
              <select
                value={form.department}
                onChange={(e) =>
                  setForm({ ...form, department: e.target.value })
                }
                className="w-full bg-slate-800 border border-sh-border rounded px-2 py-1 text-[10px] font-mono text-slate-300 outline-none"
              >
                <option value="All">All</option>
                <option value="Finance">Finance</option>
                <option value="Engineering">Engineering</option>
                <option value="Legal">Legal</option>
                <option value="Marketing">Marketing</option>
                <option value="HR">HR</option>
              </select>
            </div>
            <div>
              <label className="text-[8px] font-mono text-slate-500 uppercase tracking-wider block mb-1">
                Severity
              </label>
              <select
                value={form.severity}
                onChange={(e) => setForm({ ...form, severity: e.target.value })}
                className="w-full bg-slate-800 border border-sh-border rounded px-2 py-1 text-[10px] font-mono text-slate-300 outline-none"
              >
                <option value="HIGH">High</option>
                <option value="MEDIUM">Medium</option>
                <option value="LOW">Low</option>
              </select>
            </div>
          </div>
          <FormField
            label="Description"
            value={form.description}
            onChange={(v) => setForm({ ...form, description: v })}
            placeholder="Describe the policy rule's purpose"
          />
          <button
            onClick={handleCreate}
            disabled={!form.name || !form.service}
            className="w-full flex items-center justify-center gap-1.5 text-[10px] font-mono font-bold text-emerald-400 bg-emerald-500/10 hover:bg-emerald-500/20 border border-emerald-500/30 rounded-lg py-1.5 transition-all disabled:opacity-40"
          >
            <Plus size={10} />
            Create Rule
          </button>
        </div>
      )}

      {/* Rules List */}
      {rules.length === 0 ? (
        <div className="text-center py-8 text-slate-600">
          <Shield className="w-10 h-10 mx-auto mb-2 stroke-1" />
          <span className="text-xs font-mono">No policy rules configured</span>
        </div>
      ) : (
        <div className="space-y-2">
          {rules.map((rule) => {
            const action = ACTION_STYLES[rule.action] || ACTION_STYLES.monitor;
            return (
              <div
                key={rule.id}
                className={`bg-sh-panel border rounded-lg p-3 transition-all ${
                  rule.enabled
                    ? "border-sh-border"
                    : "border-sh-border/50 opacity-60"
                }`}
              >
                <div className="flex items-center gap-3">
                  {/* Action Badge */}
                  <div
                    className={`flex items-center gap-1 px-1.5 py-0.5 rounded text-[9px] font-mono font-bold ${action.bg} ${action.text} border ${action.border}`}
                  >
                    {action.icon}
                    {action.label}
                  </div>

                  {/* Info */}
                  <div className="flex-1 min-w-0">
                    <div className="text-xs font-mono font-bold text-slate-200">
                      {rule.name}
                    </div>
                    <div className="text-[10px] font-mono text-slate-500">
                      Service:{" "}
                      <span className="text-slate-400">{rule.service}</span>
                      {" • "}
                      Dept:{" "}
                      <span className="text-slate-400">{rule.department}</span>
                    </div>
                  </div>

                  {/* Toggle */}
                  <button
                    onClick={() => handleToggle(rule.id)}
                    className="text-slate-500 hover:text-slate-300 transition-colors"
                    title={rule.enabled ? "Disable" : "Enable"}
                  >
                    {rule.enabled ? (
                      <ToggleRight size={20} className="text-emerald-400" />
                    ) : (
                      <ToggleLeft size={20} />
                    )}
                  </button>

                  {/* Delete */}
                  <button
                    onClick={() => handleDelete(rule.id)}
                    className="text-slate-600 hover:text-red-400 transition-colors"
                    title="Delete rule"
                  >
                    <Trash2 size={14} />
                  </button>
                </div>

                {rule.description && (
                  <p className="text-[10px] text-slate-500 mt-1.5 pl-14">
                    {rule.description}
                  </p>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
};

// ═══ Sub-component ═══
const FormField = ({ label, value, onChange, placeholder }) => (
  <div>
    <label className="text-[8px] font-mono text-slate-500 uppercase tracking-wider block mb-1">
      {label}
    </label>
    <input
      type="text"
      value={value}
      onChange={(e) => onChange(e.target.value)}
      placeholder={placeholder}
      className="w-full bg-slate-800 border border-sh-border rounded px-2 py-1 text-[10px] font-mono text-slate-300 placeholder:text-slate-600 outline-none focus:border-emerald-500/40"
    />
  </div>
);

export default PolicyEngine;
