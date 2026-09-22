import React, { useState, useEffect, useRef, useCallback } from "react";
import {
  LayoutDashboard, Search, ListChecks, Clock, Bot, Settings, UserCircle2,
  Shield, ShieldAlert, ShieldCheck, Send, Loader2, Sun, Moon,
  Menu, X, RefreshCw, Check, AlertTriangle, CheckCircle,
  XCircle, MessageSquare, BarChart3, Zap
} from "lucide-react";
import jsPDF from "jspdf";
import {
  PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis,
  Tooltip, ResponsiveContainer, LineChart, Line
} from "recharts";

// ============================================================
// THEMES
// ============================================================
const DARK = {
  bg: "#0A0818", sidebar: "#0F0D24", card: "#14112E",
  border: "#2A2650", text: "#E8E6FF", textMuted: "#7B78A8",
  textDim: "#3A3760", accent: "#7C3AED", accentLight: "#A855F7",
  accentGlow: "rgba(124,58,237,0.25)", input: "#0F0D24",
  inputBorder: "#2A2650", navActive: "#1E1A40", navHover: "#16133A",
  safe: "#10B981", suspicious: "#F59E0B", scam: "#EF4444",
};
const LIGHT = {
  bg: "#F4F2FF", sidebar: "#FFFFFF", card: "#FFFFFF",
  border: "#E4E2F5", text: "#1A1740", textMuted: "#6B68A0",
  textDim: "#C8C6E8", accent: "#7C3AED", accentLight: "#A855F7",
  accentGlow: "rgba(124,58,237,0.15)", input: "#F9F8FF",
  inputBorder: "#E4E2F5", navActive: "#F0EEFF", navHover: "#F7F5FF",
  safe: "#059669", suspicious: "#D97706", scam: "#DC2626",
};

const API_BASE = "http://127.0.0.1:8000/api";
function safeStorageGet(key) {
  if (typeof window === "undefined") return "";
  try {
    return window.localStorage.getItem(key) || window.sessionStorage.getItem(key) || "";
  } catch {
    return "";
  }
}
function safeStorageSet(key, value) {
  if (typeof window === "undefined") return;
  try {
    if (value == null || value === "") {
      window.localStorage.removeItem(key);
      window.sessionStorage.removeItem(key);
      return;
    }
    window.localStorage.setItem(key, value);
  } catch {
    // ignore storage write errors
  }
}
function getStoredToken() {
  return safeStorageGet("scamShieldToken");
}
function authHeaders() {
  const token = getStoredToken();
  return token ? { Authorization: `Bearer ${token}` } : {};
}
function persistToken(token, remember = false) {
  if (!token) {
    try {
      window.localStorage.removeItem("scamShieldToken");
      window.sessionStorage.removeItem("scamShieldToken");
    } catch {
      // ignore storage write errors
    }
    return;
  }
  if (remember) {
    try {
      window.localStorage.setItem("scamShieldToken", token);
      window.sessionStorage.removeItem("scamShieldToken");
    } catch {
      // ignore storage write errors
    }
  } else {
    try {
      window.sessionStorage.setItem("scamShieldToken", token);
      window.localStorage.removeItem("scamShieldToken");
    } catch {
      // ignore storage write errors
    }
  }
}
const api = {
  register: async (username, email, password) => {
    const r = await fetch(`${API_BASE}/auth/register`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, email, password })
    });
    return r.json();
  },
  login: async (identifier, password) => {
    const r = await fetch(`${API_BASE}/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username: identifier, password })
    });
    return r.json();
  },
  scan: async (text, account = "guest") => {
    const r = await fetch(`${API_BASE}/scan`, {
      method: "POST",
      headers: { "Content-Type": "application/json", ...authHeaders() },
      body: JSON.stringify({ text, account })
    });
    return r.json();
  },
  history: async (limit = 50, account = "guest") => {
    const params = new URLSearchParams({ limit });
    if (account) params.set("account", account);
    const r = await fetch(`${API_BASE}/history?${params.toString()}`, {
      headers: authHeaders()
    });
    return r.json();
  },
  clearHistory: async (account = "guest") => {
    const r = await fetch(`${API_BASE}/history`, {
      method: "DELETE",
      headers: { "Content-Type": "application/json", ...authHeaders() },
      body: JSON.stringify({ account })
    });
    return r.json();
  },
  stats: async (account = "guest") => {
    const params = new URLSearchParams();
    if (account) params.set("account", account);
    const r = await fetch(`${API_BASE}/stats?${params.toString()}`, {
      headers: authHeaders()
    });
    return r.json();
  },
  chat: async (message, history, account = "guest") => {
    const r = await fetch(`${API_BASE}/chat`, {
      method: "POST",
      headers: { "Content-Type": "application/json", ...authHeaders() },
      body: JSON.stringify({ message, history, account })
    });
    const data = await r.json().catch(() => ({ error: "Invalid response from backend" }));
    if (!r.ok) {
      return { error: data.error || data.message || "Backend returned an error" };
    }
    return data;
  },
  bulkScan: async (text, contentType = "text/plain", account = "guest") => {
    const r = await fetch(`${API_BASE}/bulk-scan`, {
      method: "POST",
      headers: { "Content-Type": "application/json", ...authHeaders() },
      body: JSON.stringify({ text, content_type: contentType, account })
    });
    return r.json();
  },
  analyzeUpload: async (file, account = "guest") => {
    const formData = new FormData();
    formData.append("file", file);
    const r = await fetch(`${API_BASE}/analyze-upload`, {
      method: "POST",
      headers: authHeaders(),
      body: formData
    });
    return r.json();
  },
  sendReport: async (text) => {
    const r = await fetch(`${API_BASE}/report`, {
      method: "POST",
      headers: { "Content-Type": "application/json", ...authHeaders() },
      body: JSON.stringify({ text })
    });
    return r.json();
  },
  downloadReport: async (text) => {
    const r = await fetch(`${API_BASE}/report/pdf`, {
      method: "POST",
      headers: { "Content-Type": "application/json", ...authHeaders() },
      body: JSON.stringify({ text })
    });
    if (!r.ok) {
      const data = await r.json().catch(() => ({}));
      throw new Error(data.error || "Could not generate PDF report");
    }
    return r.blob();
  }
};

// ============================================================
// NAV
// ============================================================
const NAV = [
  { id: "dashboard", label: "Dashboard", Icon: LayoutDashboard },
  { id: "analyze", label: "Analyze", Icon: Search },
  { id: "batch", label: "Batch Analyze", Icon: ListChecks },
  { id: "history", label: "History", Icon: Clock },
  { id: "assistant", label: "AI Assistant", Icon: Bot },
  { id: "profile", label: "Profile", Icon: UserCircle2 },
  { id: "settings", label: "Settings", Icon: Settings },
];
const PAGE_META = {
  dashboard: { title: "Dashboard", sub: "Overview of threat detection activity" },
  analyze: { title: "Analyze Message", sub: "Scan a message or URL for threats" },
  batch: { title: "Batch Analyze", sub: "Scan multiple messages at once" },
  history: { title: "Scan History", sub: "Past analysis records" },
  assistant: { title: "AI Assistant", sub: "Ask about cybersecurity threats" },
  profile: { title: "Profile", sub: "Your account overview and scan history" },
  settings: { title: "Settings", sub: "Customize your experience" },
};

// ============================================================
// SIDEBAR
// ============================================================
function Sidebar({ page, setPage, t, collapsed, setCollapsed }) {
  return (
    <div style={{ width: collapsed ? 72 : 252, minWidth: collapsed ? 72 : 252, background: t.sidebar, borderRight: `1px solid ${t.border}`, display: "flex", flexDirection: "column", height: "100vh", position: "sticky", top: 0, transition: "width .3s cubic-bezier(.4,0,.2,1),min-width .3s cubic-bezier(.4,0,.2,1)", overflow: "hidden", zIndex: 100 }}>
      {/* Logo */}
      <div style={{ padding: collapsed ? "22px 0" : "22px 20px", borderBottom: `1px solid ${t.border}`, display: "flex", alignItems: "center", gap: 12, justifyContent: collapsed ? "center" : "flex-start" }}>
        <div style={{ width: 38, height: 38, borderRadius: 10, background: `linear-gradient(135deg, ${t.accent}, ${t.accentLight})`, display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0, boxShadow: `0 0 18px ${t.accentGlow}` }}>
          <Shield size={20} color="#fff" />
        </div>
        {!collapsed && (
          <div>
            <div style={{ color: t.text, fontWeight: 800, fontSize: 17, letterSpacing: -0.4, fontFamily: "'Space Grotesk',sans-serif" }}>Scam Shield</div>
            <div style={{ color: t.textMuted, fontSize: 11 }}>AI Security System</div>
          </div>
        )}
      </div>

      {/* Nav */}
      <nav style={{ flex: 1, padding: "14px 10px", display: "flex", flexDirection: "column", gap: 3 }}>
        {NAV.map(({ id, label, Icon }) => {
          const a = page === id;
          return (
            <button key={id} onClick={() => setPage(id)} title={collapsed ? label : ""}
              style={{ display: "flex", alignItems: "center", gap: 12, padding: collapsed ? "13px 0" : "13px 14px", justifyContent: collapsed ? "center" : "flex-start", borderRadius: 10, border: "none", cursor: "pointer", background: a ? t.navActive : "transparent", color: a ? t.accent : t.textMuted, transition: "all .2s", fontWeight: a ? 700 : 500, fontSize: 15, width: "100%", position: "relative", boxShadow: a ? `inset 0 0 0 1px ${t.accent}30` : "none" }}
              onMouseEnter={e => { if (!a) { e.currentTarget.style.background = t.navHover; e.currentTarget.style.color = t.text; } }}
              onMouseLeave={e => { if (!a) { e.currentTarget.style.background = "transparent"; e.currentTarget.style.color = t.textMuted; } }}>
              {a && <div style={{ position: "absolute", left: 0, top: "22%", bottom: "22%", width: 3, borderRadius: 2, background: t.accent }} />}
              <Icon size={20} style={{ flexShrink: 0, color: a ? t.accent : "inherit" }} />
              {!collapsed && <span style={{ fontFamily: "'Inter',sans-serif" }}>{label}</span>}
            </button>
          );
        })}
      </nav>

      {/* Collapse btn */}
      <div style={{ padding: "14px 10px", borderTop: `1px solid ${t.border}` }}>
        <button onClick={() => setCollapsed(!collapsed)}
          style={{ width: "100%", padding: "10px 0", display: "flex", alignItems: "center", justifyContent: "center", gap: 8, background: "transparent", border: "none", cursor: "pointer", color: t.textMuted, borderRadius: 8, fontSize: 13, transition: "all .2s" }}
          onMouseEnter={e => { e.currentTarget.style.background = t.navHover; e.currentTarget.style.color = t.text; }}
          onMouseLeave={e => { e.currentTarget.style.background = "transparent"; e.currentTarget.style.color = t.textMuted; }}>
          {collapsed ? <Menu size={18} /> : <><X size={15} /><span style={{ fontFamily: "'Inter',sans-serif" }}>Collapse</span></>}
        </button>
      </div>
    </div>
  );
}

// ============================================================
// TOPBAR
// ============================================================
function TopBar({ page, t, isDark, setIsDark, account }) {
  const { title, sub } = PAGE_META[page] || { title: page, sub: "" };
  return (
    <div style={{ padding: "18px 32px", borderBottom: `1px solid ${t.border}`, display: "flex", alignItems: "center", justifyContent: "space-between", background: t.bg, position: "sticky", top: 0, zIndex: 50 }}>
      <div>
        <div style={{ color: t.text, fontWeight: 800, fontSize: 22, fontFamily: "'Space Grotesk',sans-serif", letterSpacing: -0.5 }}>{title}</div>
        <div style={{ color: t.textMuted, fontSize: 13, marginTop: 2 }}>{sub}</div>
      </div>
      <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
        <div style={{ color: t.textMuted, fontSize: 13, border: `1px solid ${t.border}`, padding: "10px 14px", borderRadius: 12, background: t.card }}>{account || "guest"}</div>
        <button onClick={() => setIsDark(!isDark)}
          style={{ padding: "8px 16px", borderRadius: 10, border: `1px solid ${t.border}`, background: t.card, cursor: "pointer", display: "flex", alignItems: "center", gap: 8, color: t.textMuted, fontSize: 13, transition: "all .2s" }}
          onMouseEnter={e => e.currentTarget.style.borderColor = t.accent}
          onMouseLeave={e => e.currentTarget.style.borderColor = t.border}>
          {isDark ? <Sun size={15} /> : <Moon size={15} />}
          {isDark ? "Light Mode" : "Dark Mode"}
        </button>
      </div>
    </div>
  );
}

// ============================================================
// SHARED COMPONENTS
// ============================================================
function RiskBadge({ level, size = "sm" }) {
  const cfg = {
    Safe: { Icon: CheckCircle, color: "#10B981", bg: "rgba(16,185,129,.12)" },
    Suspicious: { Icon: AlertTriangle, color: "#F59E0B", bg: "rgba(245,158,11,.12)" },
    Scam: { Icon: XCircle, color: "#EF4444", bg: "rgba(239,68,68,.12)" },
    Phishing: { Icon: ShieldAlert, color: "#EC4899", bg: "rgba(236,72,153,.12)" },
    Error: { Icon: XCircle, color: "#6B7280", bg: "rgba(107,114,128,.12)" },
  }[level] || { Icon: CheckCircle, color: "#10B981", bg: "rgba(16,185,129,.12)" };
  const fs = size === "lg" ? 15 : 12;
  return (
    <span style={{ display: "inline-flex", alignItems: "center", gap: 5, padding: size === "lg" ? "8px 16px" : "4px 10px", borderRadius: 20, background: cfg.bg, color: cfg.color, fontSize: fs, fontWeight: 700 }}>
      <cfg.Icon size={fs + 2} />{level}
    </span>
  );
}

function StatCard({ label, value, Icon, color, t }) {
  const rgb = { "#7C3AED": "124,58,237", "#10B981": "16,185,129", "#F59E0B": "245,158,11", "#EF4444": "239,68,68" }[color] || "124,58,237";
  return (
    <div style={{ background: t.card, border: `1px solid ${t.border}`, borderRadius: 16, padding: "22px", display: "flex", alignItems: "center", gap: 18, transition: "all .2s", cursor: "default" }}
      onMouseEnter={e => { e.currentTarget.style.borderColor = color; e.currentTarget.style.boxShadow = `0 0 22px rgba(${rgb},.12)`; }}
      onMouseLeave={e => { e.currentTarget.style.borderColor = t.border; e.currentTarget.style.boxShadow = "none"; }}>
      <div style={{ width: 52, height: 52, borderRadius: 14, background: `rgba(${rgb},.12)`, display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0 }}>
        <Icon size={24} color={color} />
      </div>
      <div>
        <div style={{ color: t.textMuted, fontSize: 13, marginBottom: 4 }}>{label}</div>
        <div style={{ color: t.text, fontSize: 28, fontWeight: 800, fontFamily: "'Space Grotesk',sans-serif", letterSpacing: -0.5 }}>{value}</div>
      </div>
    </div>
  );
}

function EmptyState({ t, msg }) {
  return (
    <div style={{ textAlign: "center", padding: "48px 20px" }}>
      <div style={{ fontSize: 40, marginBottom: 14 }}>🛡️</div>
      <div style={{ color: t.textMuted, fontSize: 14 }}>{msg}</div>
    </div>
  );
}

function Spinner({ t }) {
  return (
    <div style={{ display: "flex", justifyContent: "center", alignItems: "center", height: 300 }}>
      <div style={{ width: 40, height: 40, borderRadius: "50%", border: `3px solid ${t.border}`, borderTopColor: t.accent, animation: "spin .8s linear infinite" }} />
    </div>
  );
}

function exportToCsv(rows, filename, headers) {
  if (!rows || rows.length === 0) return;

  const csvHeaders = headers || Object.keys(rows[0] || {});
  const escapeCell = (value) => {
    const text = value == null ? "" : String(value);
    const escaped = text.replace(/"/g, '""');
    return /[",\n]/.test(escaped) ? `"${escaped}"` : escaped;
  };

  const csvRows = [csvHeaders.map(escapeCell).join(",")];
  rows.forEach((row) => {
    csvRows.push(csvHeaders.map((header) => escapeCell(row[header])).join(","));
  });

  const blob = new Blob([csvRows.join("\n")], { type: "text/csv;charset=utf-8;" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
}

function exportDashboardPdf(stats, history, trendData) {
  const doc = new jsPDF({ orientation: "landscape", unit: "pt", format: "a4" });
  const now = new Date();
  const headerX = 40;
  let y = 40;

  doc.setFontSize(18);
  doc.text("Scam Shield Scan Report", headerX, y);
  y += 24;
  doc.setFontSize(10);
  doc.text(`Generated: ${now.toLocaleString()}`, headerX, y);
  y += 26;

  doc.setFontSize(12);
  doc.text("Summary", headerX, y);
  y += 18;

  const summaryLines = [
    `Total scans: ${stats?.total_scans || 0}`,
    `Safe: ${stats?.by_risk_level?.Safe || 0}`,
    `Suspicious: ${stats?.by_risk_level?.Suspicious || 0}`,
    `Scam: ${stats?.by_risk_level?.Scam || 0}`,
  ];
  summaryLines.forEach((line) => {
    doc.setFontSize(10);
    doc.text(line, headerX, y);
    y += 14;
  });

  y += 8;
  doc.setFontSize(12);
  doc.text("Recent scans", headerX, y);
  y += 18;
  const recent = history.slice(0, 5);
  recent.forEach((item) => {
    const line = `${item.input_text.slice(0, 60)} | ${item.risk_level} | ${item.confidence}% | ${item.language}`;
    doc.setFontSize(9);
    doc.text(line, headerX, y);
    y += 12;
  });

  y += 16;
  doc.setFontSize(12);
  doc.text("Daily Scan Trend (last 7 days)", headerX, y);
  y += 18;
  trendData?.forEach((item) => {
    doc.setFontSize(9);
    doc.text(`${item.day}: ${item.count}`, headerX, y);
    y += 12;
  });

  const fileName = `scam-shield-report-${now.toISOString().slice(0, 10)}.pdf`;
  doc.save(fileName);
}

// ============================================================
// DASHBOARD
// ============================================================
function DashboardPage({ t, account }) {
  const [stats, setStats] = useState(null);
  const [history, setHistory] = useState([]);
  const [loading, setLoading] = useState(true);

  const load = useCallback(async () => {
    setLoading(true);
    try { const [s, h] = await Promise.all([api.stats(account), api.history(20, account)]); setStats(s); setHistory(h); } catch { }
    setLoading(false);
  }, [account]);
  useEffect(() => { load(); }, [load]);

  if (loading) return <Spinner t={t} />;

  const pieData = [
    { name: "Safe", value: stats?.by_risk_level?.Safe || 0, color: "#10B981" },
    { name: "Suspicious", value: stats?.by_risk_level?.Suspicious || 0, color: "#F59E0B" },
    { name: "Scam", value: stats?.by_risk_level?.Scam || 0, color: "#EF4444" },
      { name: "Phishing", value: stats?.by_risk_level?.Phishing || 0, color: "#EC4899" },
  ];
  const langData = Object.entries(stats?.by_language || {}).map(([k, v]) => ({ name: k, count: v }));
  const trendData = stats?.daily_trend || [];

  return (
    <div style={{ padding: "30px 32px" }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 18 }}>
        <div>
          <div style={{ color: t.text, fontSize: 22, fontWeight: 800, fontFamily: "'Space Grotesk',sans-serif", marginBottom: 6 }}>Dashboard</div>
          <div style={{ color: t.textMuted, fontSize: 13 }}>Overview of threat detection activity</div>
        </div>
        <button onClick={() => exportDashboardPdf(stats, history, trendData)} style={{ padding: "10px 18px", borderRadius: 12, border: "none", background: `linear-gradient(135deg,${t.accent},${t.accentLight})`, color: "#fff", cursor: "pointer", fontWeight: 700, fontSize: 13 }}>
          Export Report PDF
        </button>
      </div>
      <div style={{ display: "grid", gridTemplateColumns: "repeat(4,1fr)", gap: 16, marginBottom: 26 }}>
        <StatCard label="Total Scans" value={stats?.total_scans || 0} Icon={BarChart3} color="#7C3AED" t={t} />
        <StatCard label="Safe Messages" value={stats?.by_risk_level?.Safe || 0} Icon={ShieldCheck} color="#10B981" t={t} />
        <StatCard label="Suspicious" value={stats?.by_risk_level?.Suspicious || 0} Icon={ShieldAlert} color="#F59E0B" t={t} />
          <StatCard label="Scam" value={stats?.by_risk_level?.Scam || 0} Icon={Shield} color="#EF4444" t={t} />
          <StatCard label="Phishing" value={stats?.by_risk_level?.Phishing || 0} Icon={Shield} color="#EC4899" t={t} />
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 20, marginBottom: 26 }}>
        {[
          { title: "Risk Distribution", content: pieData.some(d => d.value > 0) ? (
            <ResponsiveContainer width="100%" height={210}>
              <PieChart><Pie data={pieData} cx="50%" cy="50%" outerRadius={85} dataKey="value" label={({ name, percent }) => percent > 0 ? `${name} ${(percent*100).toFixed(0)}%` : ""}>
                {pieData.map((e, i) => <Cell key={i} fill={e.color} />)}
              </Pie><Tooltip contentStyle={{ background: t.card, border: `1px solid ${t.border}`, borderRadius: 8, color: t.text, fontSize: 12 }} /></PieChart>
            </ResponsiveContainer>
          ) : <EmptyState t={t} msg="No scan data yet" /> },
          { title: "Daily Trend", content: trendData.length > 0 ? (
            <ResponsiveContainer width="100%" height={210}>
              <LineChart data={trendData}>
                <XAxis dataKey="day" stroke={t.textMuted} tick={{ fill: t.textMuted, fontSize: 12 }} />
                <YAxis stroke={t.textMuted} tick={{ fill: t.textMuted, fontSize: 12 }} allowDecimals={false} />
                <Tooltip contentStyle={{ background: t.card, border: `1px solid ${t.border}`, borderRadius: 8, color: t.text, fontSize: 12 }} />
                <Line type="monotone" dataKey="count" stroke={t.accent} strokeWidth={2} dot={{ r: 3, fill: t.accent }} />
              </LineChart>
            </ResponsiveContainer>
          ) : <EmptyState t={t} msg="No trend data yet" /> },
          { title: "Language Breakdown", content: langData.length > 0 ? (
            <ResponsiveContainer width="100%" height={210}>
              <BarChart data={langData}>
                <XAxis dataKey="name" stroke={t.textMuted} tick={{ fill: t.textMuted, fontSize: 12 }} />
                <YAxis stroke={t.textMuted} tick={{ fill: t.textMuted, fontSize: 12 }} />
                <Tooltip contentStyle={{ background: t.card, border: `1px solid ${t.border}`, borderRadius: 8, color: t.text, fontSize: 12 }} />
                <Bar dataKey="count" fill={t.accent} radius={[6, 6, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          ) : <EmptyState t={t} msg="No scan data yet" /> },
        ].map(({ title, content }) => (
          <div key={title} style={{ background: t.card, border: `1px solid ${t.border}`, borderRadius: 16, padding: 24 }}>
            <div style={{ color: t.text, fontWeight: 700, fontSize: 15, marginBottom: 18, fontFamily: "'Space Grotesk',sans-serif" }}>{title}</div>
            {content}
          </div>
        ))}
      </div>

      <div style={{ background: t.card, border: `1px solid ${t.border}`, borderRadius: 16, padding: 24 }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 18 }}>
          <div style={{ color: t.text, fontWeight: 700, fontSize: 15, fontFamily: "'Space Grotesk',sans-serif" }}>Recent Scans</div>
          <button onClick={load} style={{ background: "none", border: "none", cursor: "pointer", color: t.textMuted, display: "flex", alignItems: "center", gap: 5, fontSize: 13 }}><RefreshCw size={15} /> Refresh</button>
        </div>
        {history.length === 0 ? <EmptyState t={t} msg="No scans yet. Go to Analyze to start!" /> : (
          <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
            {history.slice(0, 8).map(s => (
              <div key={s.id} style={{ display: "flex", alignItems: "center", gap: 14, padding: "11px 16px", borderRadius: 10, background: t.bg, border: `1px solid ${t.border}` }}>
                <RiskBadge level={s.risk_level} />
                <div style={{ flex: 1, color: t.text, fontSize: 13, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{s.input_text}</div>
                <span style={{ color: t.textMuted, fontSize: 12, textTransform: "capitalize", flexShrink: 0 }}>{s.language}</span>
                <span style={{ color: s.risk_level === "Safe" ? "#10B981" : s.risk_level === "Suspicious" ? "#F59E0B" : "#EF4444", fontSize: 13, fontWeight: 700, flexShrink: 0 }}>{s.confidence}%</span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

// ============================================================
// ANALYZE
// ============================================================
function AnalyzePage({ t, account }) {
  const [text, setText] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");
  const [reportMessage, setReportMessage] = useState("");
  const [reportError, setReportError] = useState("");
  const [reportLoading, setReportLoading] = useState(false);
  const [pdfLoading, setPdfLoading] = useState(false);
  const [extractedText, setExtractedText] = useState("");
  const [sourceMode, setSourceMode] = useState("text");

  const scan = async () => {
    if (!text.trim()) return;
    setLoading(true); setError(""); setResult(null); setExtractedText("");
    try {
      const r = await api.scan(text, account);
      if (r.error) setError(r.error); else setResult(r);
    } catch { setError("Cannot connect to backend. Make sure Flask is running on port 8000."); }
    setLoading(false);
  };

  const handleUpload = async (event) => {
    const file = event.target.files?.[0];
    if (!file) return;
    setLoading(true); setError(""); setResult(null); setExtractedText("");
    try {
      const r = await api.analyzeUpload(file, account);
      if (r.error) {
        setError(r.error);
      } else {
        setExtractedText(r.extracted_text || "");
        setText(r.extracted_text || "");
        setResult(r.result || null);
        setSourceMode("upload");
      }
    } catch {
      setError("Could not analyze the uploaded file. Please try again.");
    }
    setLoading(false);
    event.target.value = "";
  };

  const rColor = result ? { Safe: "#10B981", Suspicious: "#F59E0B", Scam: "#EF4444", Phishing: "#EC4899" }[result.risk_level] : t.accent;
  const canSendReport = Boolean(account && account !== "guest");

  const sendReport = async () => {
    if (!result || !text.trim()) return;
    setReportMessage("");
    setReportError("");
    setReportLoading(true);
    try {
      const res = await api.sendReport(text);
      if (res.error) {
        setReportError(res.error);
      } else {
        setReportMessage(res.message || "Report sent successfully to your registered email.");
      }
    } catch {
      setReportError("Unable to send email report. Make sure you are logged in and the backend is running.");
    }
    setReportLoading(false);
  };

  const downloadPdf = async () => {
    if (!result || !text.trim()) return;
    setPdfLoading(true);
    try {
      const blob = await api.downloadReport(text);
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = "scamshield-analysis.pdf";
      document.body.appendChild(link);
      link.click();
      link.remove();
      URL.revokeObjectURL(url);
    } catch (err) {
      setReportError(err.message || "Unable to generate PDF report.");
    }
    setPdfLoading(false);
  };

  return (
    <div style={{ padding: "30px 32px", maxWidth: 840 }}>
      <div style={{ background: t.card, border: `1px solid ${t.border}`, borderRadius: 16, padding: 26, marginBottom: 22 }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 10, marginBottom: 12, flexWrap: "wrap" }}>
          <label style={{ color: t.text, fontWeight: 700, fontSize: 14, fontFamily: "'Space Grotesk',sans-serif" }}>Enter message or URL to analyze</label>
          <div style={{ display: "flex", gap: 8 }}>
            <button onClick={() => setSourceMode("text")} style={{ padding: "7px 12px", borderRadius: 10, border: `1px solid ${sourceMode === "text" ? t.accent : t.border}`, background: sourceMode === "text" ? `${t.accent}16` : "transparent", color: sourceMode === "text" ? t.accent : t.textMuted, cursor: "pointer", fontSize: 12, fontWeight: 700 }}>Paste Text</button>
            <label style={{ padding: "7px 12px", borderRadius: 10, border: `1px solid ${sourceMode === "upload" ? t.accent : t.border}`, background: sourceMode === "upload" ? `${t.accent}16` : "transparent", color: sourceMode === "upload" ? t.accent : t.textMuted, cursor: "pointer", fontSize: 12, fontWeight: 700 }}>
              Upload File / Image
              <input type="file" accept=".txt,.csv,.json,.png,.jpg,.jpeg,.webp,.bmp,.tiff,.gif" onChange={handleUpload} style={{ display: "none" }} />
            </label>
          </div>
        </div>
        <textarea value={text} onChange={e => { setText(e.target.value); setSourceMode("text"); }}
          placeholder="Paste a suspicious SMS, email, or URL here..."
          rows={5}
          style={{ width: "100%", resize: "vertical", padding: "14px 16px", borderRadius: 10, border: `1.5px solid ${t.inputBorder}`, background: t.input, color: t.text, fontSize: 14, fontFamily: "'Inter',sans-serif", outline: "none", boxSizing: "border-box", transition: "border-color .2s" }}
          onFocus={e => e.target.style.borderColor = t.accent}
          onBlur={e => e.target.style.borderColor = t.inputBorder} />
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginTop: 14, flexWrap: "wrap", gap: 10 }}>
          <span style={{ color: t.textMuted, fontSize: 12 }}>{text.length} characters</span>
          <div style={{ display: "flex", gap: 10 }}>
            {text && <button onClick={() => { setText(""); setResult(null); setError(""); setExtractedText(""); setSourceMode("text"); }} style={{ padding: "10px 18px", borderRadius: 10, border: `1px solid ${t.border}`, background: "transparent", color: t.textMuted, cursor: "pointer", fontSize: 13 }}>Clear</button>}
            <button onClick={scan} disabled={loading || !text.trim()}
              style={{ padding: "10px 28px", borderRadius: 10, border: "none", background: loading || !text.trim() ? t.textDim : `linear-gradient(135deg,${t.accent},${t.accentLight})`, color: "#fff", cursor: loading || !text.trim() ? "not-allowed" : "pointer", fontWeight: 700, fontSize: 14, display: "flex", alignItems: "center", gap: 8, boxShadow: loading || !text.trim() ? "none" : `0 4px 18px ${t.accentGlow}`, transition: "all .2s" }}>
              {loading ? <><Loader2 size={16} style={{ animation: "spin .8s linear infinite" }} />Analyzing...</> : <><Search size={16} />Analyze</>}
            </button>
          </div>
        </div>
        {extractedText && (
          <div style={{ marginTop: 16, background: t.bg, border: `1px solid ${t.border}`, borderRadius: 10, padding: 12 }}>
            <div style={{ color: t.text, fontWeight: 700, fontSize: 13, marginBottom: 8 }}>Extracted text</div>
            <div style={{ color: t.textMuted, fontSize: 12, whiteSpace: "pre-wrap", lineHeight: 1.6 }}>{extractedText}</div>
          </div>
        )}
      </div>

      {error && <div style={{ background: "rgba(239,68,68,.1)", border: "1px solid rgba(239,68,68,.3)", borderRadius: 12, padding: "14px 18px", color: "#EF4444", fontSize: 14, marginBottom: 20 }}>{error}</div>}

      {result && (
        <div style={{ background: t.card, border: `1.5px solid ${rColor}50`, borderRadius: 16, padding: 26, boxShadow: `0 0 30px ${rColor}14`, animation: "fadeIn .35s ease" }}>
          <div style={{ display: "flex", alignItems: "center", gap: 16, marginBottom: 24 }}>
            <div style={{ width: 58, height: 58, borderRadius: 16, background: `${rColor}18`, display: "flex", alignItems: "center", justifyContent: "center" }}>
              {result.risk_level === "Safe" ? <ShieldCheck size={28} color={rColor} /> : result.risk_level === "Suspicious" ? <ShieldAlert size={28} color={rColor} /> : <Shield size={28} color={rColor} />}
            </div>
            <div>
              <RiskBadge level={result.risk_level} size="lg" />
              <div style={{ color: t.textMuted, fontSize: 13, marginTop: 6 }}>
                Confidence: <b style={{ color: rColor }}>{result.confidence}%</b>
                &nbsp;·&nbsp;Language: <b style={{ color: t.text, textTransform: "capitalize" }}>{result.language}</b>
                &nbsp;·&nbsp;Text Score: <b style={{ color: t.accent }}>{result.text_model_score}%</b>
              </div>
            </div>
          </div>

          <div style={{ marginBottom: 22 }}>
            <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 8 }}>
              <span style={{ color: t.textMuted, fontSize: 12 }}>Risk Score</span>
              <span style={{ color: rColor, fontSize: 12, fontWeight: 700 }}>{result.confidence}%</span>
            </div>
            <div style={{ height: 8, borderRadius: 4, background: t.border, overflow: "hidden" }}>
              <div style={{ height: "100%", borderRadius: 4, width: `${result.confidence}%`, background: `linear-gradient(90deg,${rColor}80,${rColor})`, transition: "width .8s cubic-bezier(.4,0,.2,1)" }} />
            </div>
          </div>

          <div style={{ marginBottom: 20 }}>
            <div style={{ color: t.text, fontWeight: 700, fontSize: 14, marginBottom: 12, fontFamily: "'Space Grotesk',sans-serif" }}>Detection Reasons</div>
            <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
              {result.reasons.map((r, i) => (
                <div key={i} style={{ display: "flex", gap: 10, padding: "10px 14px", borderRadius: 8, background: `${rColor}0D`, border: `1px solid ${rColor}25` }}>
                  <span style={{ color: rColor, flexShrink: 0 }}>⚑</span>
                  <span style={{ color: t.text, fontSize: 13 }}>{r}</span>
                </div>
              ))}
            </div>
          </div>

          <div style={{ marginBottom: 20, padding: "14px 16px", borderRadius: 10, background: t.bg, border: `1px solid ${t.border}` }}>
            <div style={{ color: t.text, fontWeight: 700, fontSize: 14, marginBottom: 10 }}>Explainable AI: highlighted risk terms</div>
            <HighlightedMessage text={text} terms={result.highlighted_terms} t={t} />
            <div style={{ display: "flex", gap: 14, flexWrap: "wrap", marginTop: 12, color: t.textMuted, fontSize: 11 }}>
              <span><b style={{ color: "#EF4444" }}>■</b> Phishing</span>
              <span><b style={{ color: "#F97316" }}>■</b> Spam</span>
              <span><b style={{ color: "#EC4899" }}>■</b> Urgent</span>
            </div>
          </div>

          <div style={{ marginBottom: 20 }}>
            <div style={{ color: t.text, fontWeight: 700, fontSize: 14, marginBottom: 10 }}>Ensemble classifier votes</div>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 10 }}>
              {[['Naive Bayes', 'nb'], ['Logistic Regression', 'lr'], ['LinearSVC', 'svc']].map(([label, key]) => (
                <div key={key} style={{ padding: 12, borderRadius: 10, background: t.bg, border: `1px solid ${t.border}` }}>
                  <div style={{ color: t.textMuted, fontSize: 11, marginBottom: 5 }}>{label}</div>
                  <div style={{ color: t.accent, fontWeight: 800, fontSize: 20 }}>{result.classifier_scores?.[key] ?? result.text_model_score}%</div>
                </div>
              ))}
            </div>
          </div>

          <div style={{ padding: "14px 18px", borderRadius: 10, background: `${rColor}0D`, border: `1px solid ${rColor}30` }}>
            <div style={{ color: rColor, fontWeight: 700, fontSize: 13, marginBottom: 4 }}>Recommendation</div>
            <div style={{ color: t.text, fontSize: 13 }}>{result.recommendation}</div>
          </div>

          {result.urls_analyzed?.length > 0 && (
            <div style={{ marginTop: 20 }}>
              <div style={{ color: t.text, fontWeight: 700, fontSize: 14, marginBottom: 12, fontFamily: "'Space Grotesk',sans-serif" }}>URL Analysis ({result.urls_analyzed.length} URL{result.urls_analyzed.length > 1 ? "s" : ""})</div>
              {result.urls_analyzed.map((u, i) => (
                <div key={i} style={{ padding: "12px 16px", borderRadius: 10, background: t.bg, border: `1px solid ${t.border}`, marginBottom: 8 }}>
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 6 }}>
                    <code style={{ color: t.accentLight, fontSize: 11, wordBreak: "break-all" }}>{u.url}</code>
                    <span style={{ background: u.score > .6 ? "rgba(239,68,68,.12)" : u.score > .3 ? "rgba(245,158,11,.12)" : "rgba(16,185,129,.12)", color: u.score > .6 ? "#EF4444" : u.score > .3 ? "#F59E0B" : "#10B981", padding: "2px 10px", borderRadius: 10, fontSize: 11, fontWeight: 700, flexShrink: 0, marginLeft: 8 }}>{Math.round(u.score * 100)}%</span>
                  </div>
                  {u.reasons.map((r, j) => <div key={j} style={{ color: t.textMuted, fontSize: 12 }}>• {r}</div>)}
                </div>
              ))}
            </div>
          )}

          <div style={{ marginTop: 22, display: "flex", flexDirection: "column", gap: 12 }}>
            <button onClick={downloadPdf} disabled={pdfLoading}
              style={{ width: "100%", padding: "14px 20px", borderRadius: 14, border: `1px solid ${t.accent}`, background: `${t.accent}12`, color: t.accent, fontWeight: 800, cursor: pdfLoading ? "wait" : "pointer" }}>
              {pdfLoading ? "Generating PDF..." : "Download PDF report"}
            </button>
            <button onClick={sendReport} disabled={!canSendReport || reportLoading}
              style={{ width: "100%", padding: "14px 20px", borderRadius: 14, border: "none", background: !canSendReport ? t.textDim : reportLoading ? t.border : `linear-gradient(135deg,${t.accent},${t.accentLight})`, color: "#fff", fontWeight: 800, cursor: !canSendReport || reportLoading ? "not-allowed" : "pointer", transition: "all .2s" }}>
              {reportLoading ? "Sending report..." : canSendReport ? "Send analysis report to my email" : "Login to send report to email"}
            </button>
            {reportMessage ? <div style={{ color: "#10B981", fontSize: 13 }}>{reportMessage}</div> : null}
            {reportError ? <div style={{ color: "#EF4444", fontSize: 13 }}>{reportError}</div> : null}
            {!canSendReport ? <div style={{ color: t.textMuted, fontSize: 12 }}>Create an account or login so you can receive analysis reports to your registered email address.</div> : null}
          </div>
        </div>
      )}
    </div>
  );
}

// ============================================================
// BATCH ANALYZE
// ============================================================
function BatchAnalyzePage({ t, account }) {
  const [input, setInput] = useState("");
  const [results, setResults] = useState([]);
  const [loading, setLoading] = useState(false);
  const [progress, setProgress] = useState(0);
  const [summary, setSummary] = useState(null);
  const [uploadMode, setUploadMode] = useState("paste");

  const run = async () => {
    const lines = input.split("\n").map(l => l.trim()).filter(Boolean);
    if (!lines.length) return;
    setLoading(true); setResults([]); setProgress(0); setSummary(null);
    try {
      const r = await api.bulkScan(lines.join("\n"), "text/plain", account);
      if (r.error) {
        setResults([]);
        setSummary({ error: r.error });
      } else {
        setResults(r.results || []);
        setSummary(r.summary || null);
      }
    } catch {
      setSummary({ error: "Could not reach the backend. Make sure Flask is running on port 8000." });
    }
    setLoading(false);
    setProgress(100);
  };

  const handleFileUpload = async (event) => {
    const file = event.target.files?.[0];
    if (!file) return;
    const text = await file.text();
    setInput(text);
    setUploadMode("file");
    setLoading(true); setResults([]); setProgress(0); setSummary(null);
    try {
      const r = await api.bulkScan(text, file.type || "text/plain", account);
      if (r.error) {
        setResults([]);
        setSummary({ error: r.error });
      } else {
        setResults(r.results || []);
        setSummary(r.summary || null);
      }
    } catch {
      setSummary({ error: "Could not analyze uploaded file. Please try again." });
    }
    setLoading(false);
    setProgress(100);
    event.target.value = "";
  };

  return (
    <div style={{ padding: "30px 32px" }}>
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 24 }}>
        <div style={{ background: t.card, border: `1px solid ${t.border}`, borderRadius: 16, padding: 26 }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 10 }}>
            <div style={{ color: t.text, fontWeight: 700, fontSize: 16, fontFamily: "'Space Grotesk',sans-serif" }}>Bulk Input</div>
            <div style={{ display: "flex", gap: 8 }}>
              <button onClick={() => setUploadMode("paste")} style={{ padding: "7px 12px", borderRadius: 10, border: `1px solid ${uploadMode === "paste" ? t.accent : t.border}`, background: uploadMode === "paste" ? `${t.accent}16` : "transparent", color: uploadMode === "paste" ? t.accent : t.textMuted, cursor: "pointer", fontSize: 12, fontWeight: 700 }}>Paste</button>
              <label style={{ padding: "7px 12px", borderRadius: 10, border: `1px solid ${uploadMode === "file" ? t.accent : t.border}`, background: uploadMode === "file" ? `${t.accent}16` : "transparent", color: uploadMode === "file" ? t.accent : t.textMuted, cursor: "pointer", fontSize: 12, fontWeight: 700 }}>
                Upload File
                <input type="file" accept=".txt,.csv,.json" onChange={handleFileUpload} style={{ display: "none" }} />
              </label>
            </div>
          </div>
          <div style={{ color: t.textMuted, fontSize: 13, marginBottom: 14 }}>Paste one message per line or upload a text/CSV file for faster batch scanning.</div>
          <textarea value={input} onChange={e => setInput(e.target.value)} placeholder={"Message 1\nMessage 2\nhttp://suspicious-link.tk"} rows={13}
            style={{ width: "100%", resize: "vertical", padding: 14, borderRadius: 10, border: `1.5px solid ${t.inputBorder}`, background: t.input, color: t.text, fontSize: 13, fontFamily: "'Inter',sans-serif", outline: "none", boxSizing: "border-box" }}
            onFocus={e => e.target.style.borderColor = t.accent}
            onBlur={e => e.target.style.borderColor = t.inputBorder} />
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginTop: 14 }}>
            <span style={{ color: t.textMuted, fontSize: 12 }}>{input.split("\n").filter(l => l.trim()).length} messages</span>
            <button onClick={run} disabled={loading || !input.trim()}
              style={{ padding: "10px 24px", borderRadius: 10, border: "none", background: loading || !input.trim() ? t.textDim : `linear-gradient(135deg,${t.accent},${t.accentLight})`, color: "#fff", cursor: loading || !input.trim() ? "not-allowed" : "pointer", fontWeight: 700, fontSize: 14, display: "flex", alignItems: "center", gap: 8 }}>
              {loading ? <><Loader2 size={15} style={{ animation: "spin .8s linear infinite" }} />{progress}%</> : <><ListChecks size={15} />Batch Analyze</>}
            </button>
          </div>
          {loading && <div style={{ marginTop: 14 }}><div style={{ height: 6, borderRadius: 3, background: t.border, overflow: "hidden" }}><div style={{ height: "100%", width: `${progress}%`, background: `linear-gradient(90deg,${t.accent},${t.accentLight})`, transition: "width .3s ease", borderRadius: 3 }} /></div></div>}
        </div>

        <div style={{ background: t.card, border: `1px solid ${t.border}`, borderRadius: 16, padding: 26 }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 14 }}>
            <div style={{ color: t.text, fontWeight: 700, fontSize: 16, fontFamily: "'Space Grotesk',sans-serif" }}>Results {results.length > 0 && `(${results.length})`}</div>
            {results.length > 0 && (
              <button onClick={() => exportToCsv(results.map((item) => ({ text: item.text, risk_level: item.risk_level, confidence: item.confidence, language: item.language, recommendation: item.recommendation })), "batch-scan-results.csv", ["text", "risk_level", "confidence", "language", "recommendation"])} style={{ background: "none", border: `1px solid ${t.border}`, borderRadius: 20, padding: "8px 14px", cursor: "pointer", color: t.text, fontSize: 13 }}>
                Export CSV
              </button>
            )}
          </div>
          {summary?.error ? <div style={{ color: "#EF4444", background: "rgba(239,68,68,.08)", borderRadius: 10, padding: 12 }}>{summary.error}</div> : results.length === 0 ? <EmptyState t={t} msg="Batch results will appear here" /> : (
            <>
              <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 10, marginBottom: 16 }}>
                {[
                  { label: "Safe", value: summary?.safe || 0, color: "#10B981" },
                  { label: "Suspicious", value: summary?.suspicious || 0, color: "#F59E0B" },
                  { label: "Scam", value: summary?.scam || 0, color: "#EF4444" },
                  { label: "Phishing", value: summary?.phishing || 0, color: "#EC4899" },
                ].map(item => (
                  <div key={item.label} style={{ padding: 12, borderRadius: 10, background: t.bg, border: `1px solid ${t.border}` }}>
                    <div style={{ color: t.textMuted, fontSize: 11, marginBottom: 4 }}>{item.label}</div>
                    <div style={{ color: item.color, fontWeight: 800, fontSize: 20 }}>{item.value}</div>
                  </div>
                ))}
              </div>
              <div style={{ color: t.textMuted, fontSize: 12, marginBottom: 10 }}>Processed {summary?.total || results.length} items · High risk: {summary?.high_risk || 0}</div>
              <div style={{ display: "flex", flexDirection: "column", gap: 8, maxHeight: 400, overflowY: "auto" }}>
                {results.map((r, i) => (
                  <div key={i} style={{ padding: "11px 14px", borderRadius: 10, background: t.bg, border: `1px solid ${t.border}` }}>
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 5 }}>
                      <span style={{ color: t.textMuted, fontSize: 11 }}>#{i + 1}</span>
                      <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
                        <span style={{ color: t.textMuted, fontSize: 11 }}>{r.confidence}%</span>
                        <RiskBadge level={r.risk_level} />
                      </div>
                    </div>
                    <div style={{ color: t.text, fontSize: 13, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{r.text}</div>
                  </div>
                ))}
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
}

// ============================================================
// HISTORY
// ============================================================
function HistoryPage({ t, account }) {
  const [history, setHistory] = useState([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState("All");

  const load = useCallback(async () => {
    setLoading(true);
    try { setHistory(await api.history(100, account)); } catch { }
    setLoading(false);
  }, [account]);
  useEffect(() => { load(); }, [load]);

  const filtered = filter === "All" ? history : history.filter(h => h.risk_level === filter);
  if (loading) return <Spinner t={t} />;

  return (
    <div style={{ padding: "30px 32px" }}>
      <div style={{ display: "flex", gap: 8, marginBottom: 22, flexWrap: "wrap" }}>
        {["All", "Safe", "Suspicious", "Scam", "Phishing"].map(f => (
          <button key={f} onClick={() => setFilter(f)}
            style={{ padding: "8px 18px", borderRadius: 20, border: `1.5px solid ${filter === f ? t.accent : t.border}`, background: filter === f ? `${t.accent}18` : "transparent", color: filter === f ? t.accent : t.textMuted, cursor: "pointer", fontSize: 13, fontWeight: filter === f ? 700 : 400, transition: "all .2s" }}>
            {f}{f !== "All" && ` (${history.filter(h => h.risk_level === f).length})`}
          </button>
        ))}
        <button onClick={load} style={{ marginLeft: "auto", background: "none", border: `1px solid ${t.border}`, borderRadius: 20, padding: "8px 16px", cursor: "pointer", color: t.textMuted, display: "flex", alignItems: "center", gap: 6, fontSize: 13 }}>
          <RefreshCw size={14} /> Refresh
        </button>
        <button onClick={() => exportToCsv(filtered.map((item) => ({ input_text: item.input_text, risk_level: item.risk_level, confidence: item.confidence, language: item.language, urls_found: item.urls_found, created_at: item.created_at })), "scan-history.csv", ["input_text", "risk_level", "confidence", "language", "urls_found", "created_at"])} style={{ background: "none", border: `1px solid ${t.border}`, borderRadius: 20, padding: "8px 16px", cursor: "pointer", color: t.text, fontSize: 13 }}>
          Export CSV
        </button>
        <button onClick={async () => {
            if (!window.confirm("Clear all scan history? This cannot be undone.")) return;
            try {
              await api.clearHistory(account);
              setHistory([]);
              setFilter("All");
            } catch (e) {
              console.error(e);
              alert("Could not clear history. Please try again.");
            }
          }}
          style={{ background: "none", border: `1px solid ${t.border}`, borderRadius: 20, padding: "8px 16px", cursor: "pointer", color: t.text, display: "flex", alignItems: "center", gap: 6, fontSize: 13 }}>
          Clear History
        </button>
      </div>

      {filtered.length === 0 ? (
        <div style={{ background: t.card, border: `1px solid ${t.border}`, borderRadius: 16, padding: "60px 24px" }}><EmptyState t={t} msg={filter === "All" ? "No scans yet. Go to Analyze to start!" : `No ${filter} messages found`} /></div>
      ) : (
        <div style={{ background: t.card, border: `1px solid ${t.border}`, borderRadius: 16, overflow: "hidden" }}>
          <div style={{ display: "grid", gridTemplateColumns: "110px 1fr 100px 80px 90px 140px", padding: "12px 20px", borderBottom: `1px solid ${t.border}`, color: t.textMuted, fontSize: 11, fontWeight: 700, textTransform: "uppercase", letterSpacing: .5 }}>
            <span>Risk</span><span>Message</span><span>Language</span><span>Score</span><span>URLs</span><span>Time</span>
          </div>
          <div style={{ maxHeight: 530, overflowY: "auto" }}>
            {filtered.map((h, i) => (
              <div key={h.id}
                style={{ display: "grid", gridTemplateColumns: "110px 1fr 100px 80px 90px 140px", padding: "14px 20px", borderBottom: i < filtered.length - 1 ? `1px solid ${t.border}` : "none", alignItems: "center", transition: "background .15s" }}
                onMouseEnter={e => e.currentTarget.style.background = t.navHover}
                onMouseLeave={e => e.currentTarget.style.background = "transparent"}>
                <span><RiskBadge level={h.risk_level} /></span>
                <span style={{ color: t.text, fontSize: 13, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", paddingRight: 12 }}>{h.input_text}</span>
                <span style={{ color: t.textMuted, fontSize: 12, textTransform: "capitalize" }}>{h.language}</span>
                <span style={{ color: h.risk_level === "Safe" ? "#10B981" : h.risk_level === "Suspicious" ? "#F59E0B" : "#EF4444", fontSize: 13, fontWeight: 700 }}>{h.confidence}%</span>
                <span style={{ color: t.textMuted, fontSize: 12 }}>{h.urls_found > 0 ? `${h.urls_found} URL${h.urls_found > 1 ? "s" : ""}` : "—"}</span>
                <span style={{ color: t.textMuted, fontSize: 11, display: "flex", alignItems: "center", gap: 8 }}>
                  {new Date(h.created_at + "Z").toLocaleString()}
                  <button title="Download PDF report" onClick={async () => {
                    try {
                      const blob = await api.downloadReport(h.input_text);
                      const url = URL.createObjectURL(blob);
                      const link = document.createElement("a");
                      link.href = url;
                      link.download = `scamshield-scan-${h.id}.pdf`;
                      link.click();
                      URL.revokeObjectURL(url);
                    } catch (error) {
                      console.error("PDF report failed", error);
                    }
                  }} style={{ border: `1px solid ${t.border}`, background: t.bg, color: t.accent, borderRadius: 6, padding: "3px 6px", cursor: "pointer", fontSize: 10 }}>PDF</button>
                </span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

// ============================================================
// AI ASSISTANT
// ============================================================
function AIAssistantPage({ t, account }) {
  const [msgs, setMsgs] = useState([{ role: "assistant", content: "Hello! I'm your Scam Shield AI Assistant. I can help you understand cybersecurity threats, explain phishing patterns, and answer questions about online scams in English, Sinhala, or Singlish. How can I help you today?" }]);
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const endRef = useRef(null);

  useEffect(() => { endRef.current?.scrollIntoView({ behavior: "smooth" }); }, [msgs]);

  const send = async () => {
    if (!input.trim() || loading) return;
    const msg = { role: "user", content: input };
    setMsgs(m => [...m, msg]); setInput(""); setLoading(true);
    try {
      const r = await api.chat(input, msgs, account);
      setMsgs(m => [...m, { role: "assistant", content: r.error ? `⚠️ ${r.error}` : r.response || r.message || "Sorry, I couldn't get a response." }]);
    } catch (error) {
      console.error("AI chat request failed", error);
      setMsgs(m => [...m, { role: "assistant", content: "⚠️ Could not reach the AI backend. Make sure the Flask server is running on http://127.0.0.1:8000 and that your browser can access it." }]);
    }
    setLoading(false);
  };

  const SUGGESTIONS = [
    "What are common phishing signs?",
    "How do I identify a scam SMS?",
    "What if I clicked a phishing link?",
    "Explain URL spoofing",
  ];

  return (
    <div style={{ padding: "30px 32px", display: "flex", flexDirection: "column", height: "calc(100vh - 96px)" }}>
      <div style={{ flex: 1, display: "flex", flexDirection: "column", background: t.card, border: `1px solid ${t.border}`, borderRadius: 16, overflow: "hidden" }}>
        <div style={{ flex: 1, overflowY: "auto", padding: "24px", display: "flex", flexDirection: "column", gap: 16 }}>
          {msgs.map((m, i) => (
            <div key={i} style={{ display: "flex", gap: 12, flexDirection: m.role === "user" ? "row-reverse" : "row", animation: "fadeIn .3s ease" }}>
              <div style={{ width: 36, height: 36, borderRadius: 10, flexShrink: 0, background: m.role === "user" ? `linear-gradient(135deg,${t.accent},${t.accentLight})` : `${t.accent}20`, display: "flex", alignItems: "center", justifyContent: "center" }}>
                {m.role === "user" ? <MessageSquare size={16} color="#fff" /> : <Bot size={16} color={t.accent} />}
              </div>
              <div style={{ maxWidth: "72%", padding: "12px 16px", borderRadius: m.role === "user" ? "16px 4px 16px 16px" : "4px 16px 16px 16px", background: m.role === "user" ? `linear-gradient(135deg,${t.accent},${t.accentLight})` : t.bg, border: m.role === "assistant" ? `1px solid ${t.border}` : "none", color: m.role === "user" ? "#fff" : t.text, fontSize: 14, lineHeight: 1.65 }}>
                {m.content}
              </div>
            </div>
          ))}
          {loading && (
            <div style={{ display: "flex", gap: 12 }}>
              <div style={{ width: 36, height: 36, borderRadius: 10, background: `${t.accent}20`, display: "flex", alignItems: "center", justifyContent: "center" }}><Bot size={16} color={t.accent} /></div>
              <div style={{ padding: "14px 18px", borderRadius: "4px 16px 16px 16px", background: t.bg, border: `1px solid ${t.border}`, display: "flex", gap: 5, alignItems: "center" }}>
                {[0, 1, 2].map(i => <div key={i} style={{ width: 7, height: 7, borderRadius: "50%", background: t.accent, animation: `bounce 1.2s ease infinite ${i * .2}s` }} />)}
              </div>
            </div>
          )}
          <div ref={endRef} />
        </div>

        {msgs.length === 1 && (
          <div style={{ padding: "0 24px 16px", display: "flex", flexWrap: "wrap", gap: 8 }}>
            {SUGGESTIONS.map(s => (
              <button key={s} onClick={() => setInput(s)}
                style={{ padding: "7px 14px", borderRadius: 20, border: `1px solid ${t.border}`, background: t.bg, color: t.textMuted, fontSize: 12, cursor: "pointer", transition: "all .2s" }}
                onMouseEnter={e => { e.currentTarget.style.borderColor = t.accent; e.currentTarget.style.color = t.accent; }}
                onMouseLeave={e => { e.currentTarget.style.borderColor = t.border; e.currentTarget.style.color = t.textMuted; }}>
                {s}
              </button>
            ))}
          </div>
        )}

        <div style={{ padding: "16px 24px", borderTop: `1px solid ${t.border}`, display: "flex", gap: 12 }}>
          <input value={input} onChange={e => setInput(e.target.value)} onKeyDown={e => e.key === "Enter" && !e.shiftKey && send()}
            placeholder="Ask about cybersecurity threats..."
            style={{ flex: 1, padding: "12px 16px", borderRadius: 10, border: `1.5px solid ${t.inputBorder}`, background: t.input, color: t.text, fontSize: 14, outline: "none", transition: "border-color .2s" }}
            onFocus={e => e.target.style.borderColor = t.accent}
            onBlur={e => e.target.style.borderColor = t.inputBorder} />
          <button onClick={send} disabled={loading || !input.trim()}
            style={{ width: 46, height: 46, borderRadius: 10, border: "none", background: loading || !input.trim() ? t.textDim : `linear-gradient(135deg,${t.accent},${t.accentLight})`, cursor: loading || !input.trim() ? "not-allowed" : "pointer", display: "flex", alignItems: "center", justifyContent: "center", boxShadow: loading || !input.trim() ? "none" : `0 4px 16px ${t.accentGlow}` }}>
            <Send size={18} color="#fff" />
          </button>
        </div>
      </div>
    </div>
  );
}

// ============================================================
// PROFILE
// ============================================================
function ProfilePage({ t, account, setAccount, setToken, rememberMe, setRememberMe }) {
  const [profileName, setProfileName] = useState(account || "guest");
  const [stats, setStats] = useState(null);
  const [history, setHistory] = useState([]);
  const [loading, setLoading] = useState(true);
  const [authMode, setAuthMode] = useState("login");
  const [username, setUsername] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [authError, setAuthError] = useState("");
  const [authMessage, setAuthMessage] = useState("");
  const [authLoading, setAuthLoading] = useState(false);

  const loadProfile = useCallback(async (name) => {
    setLoading(true);
    try {
      const [s, h] = await Promise.all([api.stats(name), api.history(8, name)]);
      setStats(s);
      setHistory(h);
    } catch {
      setStats(null);
      setHistory([]);
    }
    setLoading(false);
  }, []);

  useEffect(() => {
    const nextName = account || "guest";
    setProfileName(nextName);
    loadProfile(nextName);
  }, [account, loadProfile]);

  const handleAuth = async () => {
    setAuthError("");
    setAuthMessage("");

    if (!username.trim() || !password.trim() || (authMode === "register" && !email.trim())) {
      setAuthError("Please fill in all fields before continuing.");
      return;
    }

    setAuthLoading(true);
    try {
      const res = authMode === "login"
        ? await api.login(username.trim(), password)
        : await api.register(username.trim(), email.trim(), password);

      if (res.error) {
        setAuthError(res.error);
      } else {
        const nextAccount = res.account || username.trim();
        setAccount(nextAccount);
        setProfileName(nextAccount);
        setToken(res.token || "");
        persistToken(res.token || "", rememberMe);
        setAuthMessage(authMode === "login" ? "Logged in successfully." : "Account created successfully.");
        setUsername("");
        setPassword("");
        if (authMode === "register") setEmail("");
        loadProfile(nextAccount);
      }
    } catch {
      setAuthError("Could not reach the backend. Make sure Flask is running on port 8000.");
    }
    setAuthLoading(false);
  };

  const handleLogout = () => {
    setAccount("guest");
    setProfileName("guest");
    setToken("");
    persistToken("", false);
    setAuthMessage("Logged out. You can continue as guest or log in again.");
    loadProfile("guest");
  };

  const clearProfileHistory = async () => {
    const nextName = (profileName || "").trim() || "guest";
    try {
      await api.clearHistory(nextName);
      loadProfile(nextName);
    } catch {
      alert("Could not clear profile history. Please try again.");
    }
  };

  return (
    <div style={{ padding: "30px 32px", maxWidth: 980 }}>
      <div style={{ display: "grid", gridTemplateColumns: "1.1fr 0.9fr", gap: 20, marginBottom: 20 }}>
        <div style={{ background: t.card, border: `1px solid ${t.border}`, borderRadius: 16, padding: 24 }}>
          <div style={{ color: t.text, fontWeight: 800, fontSize: 16, marginBottom: 12, fontFamily: "'Space Grotesk',sans-serif" }}>Account Login & Registration</div>
          <div style={{ color: t.textMuted, fontSize: 13, marginBottom: 16 }}>Create a new account or sign in to keep your analysis history saved under your profile.</div>

          <div style={{ display: "flex", background: t.bg, borderRadius: 12, padding: 4, marginBottom: 18 }}>
            {[{ id: "login", label: "Login" }, { id: "register", label: "Create Account" }].map(({ id, label }) => (
              <button key={id} onClick={() => { setAuthMode(id); setAuthError(""); setAuthMessage(""); }}
                style={{ flex: 1, padding: "10px 12px", borderRadius: 10, border: "none", background: authMode === id ? t.accent : "transparent", color: authMode === id ? "#fff" : t.textMuted, fontWeight: 700, cursor: "pointer" }}>
                {label}
              </button>
            ))}
          </div>

          <label style={{ display: "block", color: t.text, fontWeight: 700, fontSize: 13, marginBottom: 8 }}>{authMode === "login" ? "Username or Email" : "Username"}</label>
          <input value={username} onChange={e => setUsername(e.target.value)} placeholder={authMode === "login" ? "Enter username or email" : "Enter username"}
            style={{ width: "100%", padding: "12px 14px", borderRadius: 10, border: `1px solid ${t.border}`, background: t.input, color: t.text, marginBottom: 12, outline: "none" }} />

          {authMode === "register" ? (
            <>
              <label style={{ display: "block", color: t.text, fontWeight: 700, fontSize: 13, marginBottom: 8 }}>Email</label>
              <input value={email} onChange={e => setEmail(e.target.value)} placeholder="Enter email address"
                style={{ width: "100%", padding: "12px 14px", borderRadius: 10, border: `1px solid ${t.border}`, background: t.input, color: t.text, marginBottom: 12, outline: "none" }} />
            </>
          ) : null}

          <label style={{ display: "block", color: t.text, fontWeight: 700, fontSize: 13, marginBottom: 8 }}>Password</label>
          <input type="password" value={password} onChange={e => setPassword(e.target.value)} placeholder="Enter password"
            style={{ width: "100%", padding: "12px 14px", borderRadius: 10, border: `1px solid ${t.border}`, background: t.input, color: t.text, marginBottom: 14, outline: "none" }} />

          <label style={{ display: "flex", alignItems: "center", gap: 10, color: t.textMuted, fontSize: 13, marginBottom: 14 }}>
            <input type="checkbox" checked={rememberMe} onChange={e => setRememberMe(e.target.checked)}
              style={{ width: 16, height: 16, accentColor: t.accent, cursor: "pointer" }} />
            Remember me on this device
          </label>

          {authError ? <div style={{ color: "#EF4444", fontSize: 13, marginBottom: 12 }}>{authError}</div> : null}
          {authMessage ? <div style={{ color: "#10B981", fontSize: 13, marginBottom: 12 }}>{authMessage}</div> : null}

          <button onClick={handleAuth} disabled={authLoading}
            style={{ width: "100%", padding: "12px 16px", borderRadius: 12, border: "none", background: authLoading ? t.textDim : `linear-gradient(135deg,${t.accent},${t.accentLight})`, color: "#fff", fontWeight: 800, cursor: authLoading ? "not-allowed" : "pointer" }}>
            {authLoading ? "Please wait..." : authMode === "login" ? "Login" : "Create Account"}
          </button>

          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginTop: 20, gap: 12, flexWrap: "wrap" }}>
            <div style={{ color: t.textMuted, fontSize: 13 }}>Current active profile: <b style={{ color: t.text }}>{account || "guest"}</b></div>
            {account !== "guest" ? (
              <button onClick={handleLogout} style={{ padding: "10px 16px", borderRadius: 10, border: "none", background: "rgba(239,68,68,0.1)", color: "#EF4444", cursor: "pointer", fontWeight: 700 }}>
                Logout
              </button>
            ) : null}
          </div>
        </div>

        <div style={{ background: t.card, border: `1px solid ${t.border}`, borderRadius: 16, padding: 24 }}>
          <div style={{ color: t.text, fontWeight: 800, fontSize: 16, marginBottom: 12, fontFamily: "'Space Grotesk',sans-serif" }}>Profile Summary</div>
          {loading ? <Spinner t={t} /> : (
            <div style={{ display: "grid", gap: 10 }}>
              <div style={{ padding: "12px 14px", borderRadius: 10, background: t.bg, border: `1px solid ${t.border}` }}>
                <div style={{ color: t.textMuted, fontSize: 12, marginBottom: 4 }}>Total Scans</div>
                <div style={{ color: t.text, fontSize: 24, fontWeight: 800 }}>{stats?.total_scans || 0}</div>
              </div>
              <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 10 }}>
                {[
                  { label: "Safe", value: stats?.by_risk_level?.Safe || 0, color: "#10B981" },
                  { label: "Suspicious", value: stats?.by_risk_level?.Suspicious || 0, color: "#F59E0B" },
                  { label: "Scam", value: stats?.by_risk_level?.Scam || 0, color: "#EF4444" },
                ].map(item => (
                  <div key={item.label} style={{ padding: "12px 10px", borderRadius: 10, background: t.bg, border: `1px solid ${t.border}` }}>
                    <div style={{ color: t.textMuted, fontSize: 11, marginBottom: 4 }}>{item.label}</div>
                    <div style={{ color: item.color, fontSize: 18, fontWeight: 800 }}>{item.value}</div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>

      <div style={{ background: t.card, border: `1px solid ${t.border}`, borderRadius: 16, padding: 24 }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 14 }}>
          <div style={{ color: t.text, fontWeight: 800, fontSize: 16, fontFamily: "'Space Grotesk',sans-serif" }}>Recent Activity</div>
          <button onClick={clearProfileHistory} style={{ background: "none", border: `1px solid ${t.border}`, borderRadius: 20, padding: "8px 14px", color: t.text, cursor: "pointer" }}>Clear History</button>
        </div>
        {history.length === 0 ? <EmptyState t={t} msg="No scans for this profile yet." /> : (
          <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
            {history.map(item => (
              <div key={item.id} style={{ display: "flex", alignItems: "center", gap: 12, padding: "10px 12px", borderRadius: 10, background: t.bg, border: `1px solid ${t.border}` }}>
                <RiskBadge level={item.risk_level} />
                <div style={{ flex: 1, color: t.text, fontSize: 13, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{item.input_text}</div>
                <span style={{ color: t.textMuted, fontSize: 12, textTransform: "capitalize" }}>{item.language}</span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

// ============================================================
// SETTINGS
// ============================================================
function SettingsPage({ t, isDark, setIsDark }) {
  const [saved, setSaved] = useState(false);
  const [aiEnabled, setAiEnabled] = useState(true);
  const [ocrEnabled, setOcrEnabled] = useState(true);
  const [historyEnabled, setHistoryEnabled] = useState(true);
  const [notificationsEnabled, setNotificationsEnabled] = useState(true);

  useEffect(() => {
    const savedAi = safeStorageGet("scamShieldAiEnabled");
    const savedOcr = safeStorageGet("scamShieldOcrEnabled");
    const savedHistory = safeStorageGet("scamShieldHistoryEnabled");
    const savedNotifications = safeStorageGet("scamShieldNotificationsEnabled");
    if (savedAi !== "") setAiEnabled(savedAi === "true");
    if (savedOcr !== "") setOcrEnabled(savedOcr === "true");
    if (savedHistory !== "") setHistoryEnabled(savedHistory === "true");
    if (savedNotifications !== "") setNotificationsEnabled(savedNotifications === "true");
  }, []);

  const save = () => {
    safeStorageSet("scamShieldAiEnabled", aiEnabled ? "true" : "false");
    safeStorageSet("scamShieldOcrEnabled", ocrEnabled ? "true" : "false");
    safeStorageSet("scamShieldHistoryEnabled", historyEnabled ? "true" : "false");
    safeStorageSet("scamShieldNotificationsEnabled", notificationsEnabled ? "true" : "false");
    setSaved(true);
    setTimeout(() => setSaved(false), 2000);
  };

  const cardStyle = {
    background: t.card,
    border: `1px solid ${t.border}`,
    borderRadius: 18,
    padding: "26px 28px",
    marginBottom: 22,
    boxShadow: isDark ? "0 20px 60px rgba(0,0,0,0.15)" : "0 16px 40px rgba(0,0,0,0.08)"
  };

  const toggleButton = (enabled) => ({
    padding: "12px 22px",
    borderRadius: 999,
    border: "none",
    background: enabled ? t.accent : t.border,
    color: enabled ? "#fff" : t.text,
    cursor: "pointer",
    fontWeight: 700,
    minWidth: 110,
    transition: "all .2s"
  });

  return (
    <div style={{ padding: "30px 32px", maxWidth: 760 }}>
      <div style={{ ...cardStyle, marginBottom: 28 }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 16, marginBottom: 16 }}>
          <div>
            <div style={{ fontSize: 22, fontWeight: 800, color: t.text }}>App Settings</div>
            <div style={{ marginTop: 8, color: t.textMuted, lineHeight: 1.7 }}>Configure the main app experience, appearance, and feature controls from one modern panel.</div>
          </div>
          <button onClick={save} style={{ padding: "12px 24px", borderRadius: 12, border: "none", background: saved ? "#10B981" : `linear-gradient(135deg,${t.accent},${t.accentLight})`, color: "#fff", fontSize: 13, fontWeight: 700, cursor: "pointer", minWidth: 150 }}>{saved ? "Saved" : "Save Preferences"}</button>
        </div>
      </div>

      <div style={cardStyle}>
        <div style={{ fontSize: 16, fontWeight: 800, color: t.text, marginBottom: 16 }}>Appearance</div>
        <div style={{ display: "grid", gap: 16, gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))" }}>
          {[{ label: "Dark", val: true }, { label: "Light", val: false }].map(({ label, val }) => (
            <button key={label} onClick={() => setIsDark(val)} style={{ padding: "18px 20px", borderRadius: 16, border: `1px solid ${t.border}`, background: isDark === val ? t.accent : t.bg, color: isDark === val ? "#fff" : t.text, cursor: "pointer", textAlign: "left", minHeight: 100, display: "flex", flexDirection: "column", justifyContent: "space-between" }}>
              <div style={{ fontSize: 15, fontWeight: 800 }}>{label}</div>
              <div style={{ marginTop: 8, color: isDark === val ? "rgba(255,255,255,0.8)" : t.textMuted, fontSize: 13 }}>Use the {label.toLowerCase()} theme across the app.</div>
            </button>
          ))}
        </div>
      </div>

      <div style={cardStyle}>
        <div style={{ fontSize: 16, fontWeight: 800, color: t.text, marginBottom: 16 }}>Features</div>
        <div style={{ display: "grid", gap: 16 }}>
          {[
            { label: "AI Assistant", value: aiEnabled, setValue: setAiEnabled, desc: "Enable intelligent chat responses for the assistant." },
            { label: "OCR Upload", value: ocrEnabled, setValue: setOcrEnabled, desc: "Allow image uploads to extract text automatically." },
            { label: "Save Scan History", value: historyEnabled, setValue: setHistoryEnabled, desc: "Store your scan history locally for later review." },
            { label: "Notifications", value: notificationsEnabled, setValue: setNotificationsEnabled, desc: "Receive app alerts and scan status messages." }
          ].map(({ label, value, setValue, desc }) => (
            <div key={label} style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "18px 20px", borderRadius: 16, background: isDark ? "rgba(255,255,255,0.03)" : "#F8F8FC" }}>
              <div>
                <div style={{ fontSize: 15, fontWeight: 700, color: t.text }}>{label}</div>
                <div style={{ marginTop: 6, color: t.textMuted, fontSize: 13 }}>{desc}</div>
              </div>
              <button onClick={() => setValue(!value)} style={toggleButton(value)}>{value ? "On" : "Off"}</button>
            </div>
          ))}
        </div>
      </div>

      <div style={cardStyle}>
        <div style={{ fontSize: 16, fontWeight: 800, color: t.text, marginBottom: 16 }}>System</div>
        <div style={{ display: "grid", gap: 12 }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "18px 20px", borderRadius: 16, background: isDark ? "rgba(255,255,255,0.03)" : "#F8F8FC" }}>
            <div>
              <div style={{ fontSize: 15, fontWeight: 700, color: t.text }}>Backend URL</div>
              <div style={{ marginTop: 6, color: t.textMuted, fontSize: 13 }}>Flask server address used by the app.</div>
            </div>
            <code style={{ color: t.accent, background: t.bg, padding: "8px 12px", borderRadius: 10, fontSize: 13, border: `1px solid ${t.border}` }}>http://127.0.0.1:8000</code>
          </div>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "18px 20px", borderRadius: 16, background: isDark ? "rgba(255,255,255,0.03)" : "#F8F8FC" }}>
            <div>
              <div style={{ fontSize: 15, fontWeight: 700, color: t.text }}>App Version</div>
              <div style={{ marginTop: 6, color: t.textMuted, fontSize: 13 }}>Stable 1.0.0.</div>
            </div>
            <div style={{ color: t.textMuted, fontWeight: 700 }}>v1.0.0</div>
          </div>
        </div>
      </div>
    </div>
  );
}

// ============================================================
// ERROR BOUNDARY
// ============================================================
class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }

  componentDidCatch(error, errorInfo) {
    console.error("App crashed", error, errorInfo);
  }

  render() {
    if (this.state.hasError) {
      return (
        <div style={{ minHeight: "100vh", display: "flex", alignItems: "center", justifyContent: "center", background: "#0A0818", color: "#E8E6FF", padding: 24 }}>
          <div style={{ maxWidth: 460, width: "100%", background: "#14112E", border: "1px solid #2A2650", borderRadius: 24, padding: 28, textAlign: "center" }}>
            <div style={{ fontSize: 42, marginBottom: 12 }}>⚠️</div>
            <div style={{ fontSize: 20, fontWeight: 800, marginBottom: 8 }}>Something went wrong</div>
            <div style={{ color: "#7B78A8", fontSize: 14, lineHeight: 1.6, marginBottom: 18 }}>
              The app hit an unexpected error. Refreshing usually fixes it, and the fallback UI will stay visible instead of going blank.
            </div>
            <button onClick={() => window.location.reload()} style={{ padding: "10px 16px", borderRadius: 10, border: "none", background: "linear-gradient(135deg,#7C3AED,#A855F7)", color: "#fff", cursor: "pointer", fontWeight: 700 }}>
              Reload app
            </button>
          </div>
        </div>
      );
    }
    return this.props.children;
  }
}

// ============================================================
// AUTH SCREEN
// ============================================================
function AuthScreen({ t, onAuth }) {
  const [mode, setMode] = useState("login");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const submit = async () => {
    if (!username.trim() || !password.trim()) {
      setError("Please enter both username and password.");
      return;
    }

    setLoading(true);
    setError("");
    try {
      const res = mode === "login"
        ? await api.login(username.trim(), password)
        : await api.register(username.trim(), password);

      if (res.error) {
        setError(res.error);
      } else {
        onAuth(res.account || username.trim());
      }
    } catch {
      setError("Could not reach the backend. Make sure Flask is running on port 8000.");
    }
    setLoading(false);
  };

  return (
    <div style={{ minHeight: "100vh", display: "flex", alignItems: "center", justifyContent: "center", background: t.bg, padding: 24 }}>
      <div style={{ width: "100%", maxWidth: 460, background: t.card, border: `1px solid ${t.border}`, borderRadius: 24, padding: 32, boxShadow: `0 16px 40px ${t.accentGlow}` }}>
        <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 14 }}>
          <div style={{ width: 44, height: 44, borderRadius: 12, background: `linear-gradient(135deg, ${t.accent}, ${t.accentLight})`, display: "flex", alignItems: "center", justifyContent: "center" }}>
            <Shield size={22} color="#fff" />
          </div>
          <div>
            <div style={{ color: t.text, fontSize: 22, fontWeight: 800, fontFamily: "'Space Grotesk',sans-serif" }}>Scam Shield</div>
            <div style={{ color: t.textMuted, fontSize: 13 }}>Secure your inbox with account-based analysis history</div>
          </div>
        </div>

        <div style={{ display: "flex", background: t.bg, borderRadius: 12, padding: 4, marginBottom: 18 }}>
          {[
            { id: "login", label: "Login" },
            { id: "register", label: "Create Account" }
          ].map(({ id, label }) => (
            <button key={id} onClick={() => { setMode(id); setError(""); }} style={{ flex: 1, padding: "10px 12px", borderRadius: 10, border: "none", background: mode === id ? t.accent : "transparent", color: mode === id ? "#fff" : t.textMuted, fontWeight: 700, cursor: "pointer" }}>
              {label}
            </button>
          ))}
        </div>

        <label style={{ display: "block", color: t.text, fontWeight: 700, fontSize: 13, marginBottom: 8 }}>Username</label>
        <input value={username} onChange={e => setUsername(e.target.value)} placeholder="Enter username" style={{ width: "100%", padding: "12px 14px", borderRadius: 10, border: `1px solid ${t.border}`, background: t.input, color: t.text, marginBottom: 12, outline: "none" }} />

        <label style={{ display: "block", color: t.text, fontWeight: 700, fontSize: 13, marginBottom: 8 }}>Password</label>
        <input type="password" value={password} onChange={e => setPassword(e.target.value)} placeholder="Enter password" style={{ width: "100%", padding: "12px 14px", borderRadius: 10, border: `1px solid ${t.border}`, background: t.input, color: t.text, marginBottom: 14, outline: "none" }} />

        {error ? <div style={{ color: "#EF4444", fontSize: 13, marginBottom: 12 }}>{error}</div> : null}

        <button onClick={submit} disabled={loading} style={{ width: "100%", padding: "12px 16px", borderRadius: 12, border: "none", background: loading ? t.textDim : `linear-gradient(135deg,${t.accent},${t.accentLight})`, color: "#fff", fontWeight: 800, cursor: loading ? "not-allowed" : "pointer" }}>
          {loading ? "Please wait..." : mode === "login" ? "Login" : "Create Account"}
        </button>
      </div>
    </div>
  );
}

// ============================================================
// APP ROOT
// ============================================================
export default function App() {
  const [page, setPage] = useState("dashboard");
  const [isDark, setIsDark] = useState(() => {
    try {
      return window.localStorage.getItem("scamShieldTheme") !== "light";
    } catch {
      return true;
    }
  });
  const [collapsed, setCollapsed] = useState(false);
  const [animating, setAnimating] = useState(false);
  const [rememberMe, setRememberMe] = useState(() => {
    try {
      return window.localStorage.getItem("scamShieldRemember") === "true";
    } catch {
      return false;
    }
  });
  const [token, setToken] = useState(() => safeStorageGet("scamShieldToken"));
  const [account, setAccount] = useState(() => {
    try {
      return window.localStorage.getItem("scamShieldAccount") || window.sessionStorage.getItem("scamShieldAccount") || "guest";
    } catch {
      return "guest";
    }
  });

  useEffect(() => {
    try {
      if (!token) {
        window.localStorage.removeItem("scamShieldToken");
        window.sessionStorage.removeItem("scamShieldToken");
      } else if (rememberMe) {
        window.localStorage.setItem("scamShieldToken", token);
        window.sessionStorage.removeItem("scamShieldToken");
      } else {
        window.sessionStorage.setItem("scamShieldToken", token);
        window.localStorage.removeItem("scamShieldToken");
      }
    } catch {
      // ignore storage errors
    }
  }, [token, rememberMe]);

  useEffect(() => {
    try {
      window.localStorage.setItem("scamShieldRemember", rememberMe ? "true" : "false");
    } catch {
      // ignore storage errors
    }
  }, [rememberMe]);

  useEffect(() => {
    try {
      if (rememberMe) {
        window.localStorage.setItem("scamShieldAccount", account);
        window.sessionStorage.removeItem("scamShieldAccount");
      } else {
        window.sessionStorage.setItem("scamShieldAccount", account);
        window.localStorage.removeItem("scamShieldAccount");
      }
    } catch {
      // ignore storage errors
    }
  }, [account, rememberMe]);

  useEffect(() => {
    try {
      window.localStorage.setItem("scamShieldTheme", isDark ? "dark" : "light");
    } catch {
      // ignore storage errors
    }
  }, [isDark]);

  const t = isDark ? DARK : LIGHT;

  const navigate = (p) => {
    if (p === page) return;
    setAnimating(true);
    setTimeout(() => { setPage(p); setAnimating(false); }, 140);
  };

  const pages = {
    dashboard: <DashboardPage t={t} account={account} />,
    analyze: <AnalyzePage t={t} account={account} />,
    batch: <BatchAnalyzePage t={t} account={account} />,
    history: <HistoryPage t={t} account={account} />,
    assistant: <AIAssistantPage t={t} account={account} />,
    profile: <ProfilePage t={t} account={account} setAccount={setAccount} setToken={setToken} rememberMe={rememberMe} setRememberMe={setRememberMe} />,
    settings: <SettingsPage t={t} isDark={isDark} setIsDark={setIsDark} account={account} setAccount={setAccount} />,
  };

  return (
    <ErrorBoundary>
      <style>{`
        *{margin:0;padding:0;box-sizing:border-box}
        body{font-family:'Inter',sans-serif;background:${t.bg}}
        ::-webkit-scrollbar{width:5px;height:5px}
        ::-webkit-scrollbar-track{background:transparent}
        ::-webkit-scrollbar-thumb{background:${t.border};border-radius:3px}
        @keyframes spin{to{transform:rotate(360deg)}}
        @keyframes bounce{0%,80%,100%{transform:scale(0)}40%{transform:scale(1)}}
        @keyframes fadeIn{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:none}}
        @keyframes pageOut{from{opacity:1}to{opacity:0;transform:translateY(-6px)}}
        @keyframes pageIn{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:none}}
      `}</style>
      <div style={{ display: "flex", height: "100vh", background: t.bg, overflow: "hidden" }}>
        <Sidebar page={page} setPage={navigate} t={t} collapsed={collapsed} setCollapsed={setCollapsed} />
        <div style={{ flex: 1, display: "flex", flexDirection: "column", overflow: "hidden" }}>
          <TopBar page={page} t={t} isDark={isDark} setIsDark={setIsDark} account={account} />
          <div style={{ flex: 1, overflowY: "auto", animation: animating ? "pageOut .14s ease forwards" : "pageIn .3s ease" }}>
            {pages[page]}
          </div>
        </div>
      </div>
    </ErrorBoundary>
  );
}

function HighlightedMessage({ text, terms, t }) {
  if (!terms?.length) return <div style={{ color: t.textMuted, fontSize: 13, whiteSpace: "pre-wrap" }}>{text}</div>;
  const parts = [];
  let cursor = 0;
  terms.forEach((term, index) => {
    if (term.start < cursor) return;
    if (term.start > cursor) parts.push(<span key={`text-${index}`}>{text.slice(cursor, term.start)}</span>);
    const color = term.category === "phishing" ? "#EF4444" : term.category === "spam" ? "#F97316" : "#EC4899";
    parts.push(<mark key={`term-${index}`} style={{ background: `${color}28`, color, borderBottom: `2px solid ${color}`, borderRadius: 3, padding: "1px 3px" }}>{text.slice(term.start, term.end)}</mark>);
    cursor = term.end;
  });
  if (cursor < text.length) parts.push(<span key="tail">{text.slice(cursor)}</span>);
  return <div style={{ color: t.text, fontSize: 13, lineHeight: 1.7, whiteSpace: "pre-wrap" }}>{parts}</div>;
}