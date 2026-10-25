import React, { useState, useEffect, useCallback } from "react";
import MasterCyberConsole from "./MasterCyberConsole.jsx";
import PdfViewerModal from "./PdfViewerModal.jsx";
import SimulationToolboxModal from "./SimulationToolboxModal.jsx";

function parseHashRoute(hash) {
  const clean = (hash || "#/overview").replace(/^#\/?/, "");
  const parts = clean.split("/").filter(Boolean);
  if (parts.length === 0) return { page: "overview" };
  if (parts[0] === "master") return { page: "master" };
  if (parts[0] === "copilot") return { page: "copilot" };
  if (parts[0] === "reports") return { page: "copilot" };
  if (parts[0] === "vigil" || parts[0] === "proact") return { page: "vigil" };
  if (parts[0] === "sentra" || parts[0] === "radar") return { page: "sentra" };
  if (parts[0] === "polaris" || parts[0] === "pulse") return { page: "polaris" };
  if (parts[0] === "assets") return { page: "assets" };
  if (parts[0] === "agents") return { page: "agents" };
  return { page: parts[0] };
}

const COPILOT_PROMPTS = [
  "Which hosts are quarantined?",
  "List critical CVEs",
  "Summarize fleet posture",
  "Explain agent negotiation",
  "Show failing POLARIS compliance controls",
  "List high-risk SENTRA data exposures",
];

const REPORT_WINDOWS = [
  "Last 15 Minutes",
  "Last 30 Minutes",
  "Last 1 Hour",
  "Full Run (All Batches)",
];

function StatusPill({ level, label }) {
  const norm = (level || "info").toLowerCase();
  let cls = "neutral";
  if (
    norm.includes("crit") ||
    norm === "fail" ||
    norm.includes("risk") ||
    norm.includes("contain") ||
    norm.includes("quarant")
  ) {
    cls = "critical";
  } else if (
    norm.includes("high") ||
    norm.includes("warn") ||
    norm.includes("elevat") ||
    norm.includes("vuln")
  ) {
    cls = "high";
  } else if (
    norm.includes("med") ||
    norm.includes("fair") ||
    norm.includes("progress") ||
    norm.includes("susp")
  ) {
    cls = "medium";
  } else if (
    norm.includes("low") ||
    norm === "pass" ||
    norm.includes("good") ||
    norm.includes("resolv") ||
    norm.includes("nominal")
  ) {
    cls = "pass";
  } else if (norm.includes("info") || norm === "open") {
    cls = "info";
  }

  return (
    <span className={`soc-pill ${cls}`}>
      <span>●</span>
      {label || (level || "UNKNOWN").toString().toUpperCase()}
    </span>
  );
}

function RingGaugeCard({
  title,
  score,
  status,
  subtitle,
  metaLeft,
  metaRight,
  actionLabel,
  onAction,
}) {
  const val = Math.max(0, Math.min(100, Number(score || 0)));
  const r = 32;
  const c = 2 * Math.PI * r;
  const offset = c - (val / 100) * c;

  let strokeColor = "var(--status-pass)";
  if (val < 50) strokeColor = "var(--sev-critical)";
  else if (val < 75) strokeColor = "var(--sev-medium)";
  else if (val < 90) strokeColor = "var(--accent-cyan)";

  return (
    <div className="soc-card gauge-box">
      <div
        style={{
          width: "100%",
          display: "flex",
          justifyContent: "space-between",
          alignItems: "flex-start",
        }}
      >
        <div style={{ textAlign: "left" }}>
          <div style={{ fontSize: 13, fontWeight: 700, color: "var(--text-main)" }}>
            {title}
          </div>
          <div style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 2 }}>
            {subtitle}
          </div>
        </div>
        <StatusPill level={status} label={status} />
      </div>

      <div className="gauge-body">
        <div
          style={{
            position: "relative",
            width: 82,
            height: 82,
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
          }}
        >
          <svg className="gauge-ring-svg" viewBox="0 0 82 82">
            <circle
              cx="41"
              cy="41"
              r={r}
              fill="none"
              stroke="var(--border-subtle)"
              strokeWidth="7"
            />
            <circle
              cx="41"
              cy="41"
              r={r}
              fill="none"
              stroke={strokeColor}
              strokeWidth="7"
              strokeLinecap="round"
              strokeDasharray={c}
              strokeDashoffset={offset}
            />
          </svg>
          <div
            style={{
              position: "absolute",
              fontSize: 18,
              fontWeight: 800,
              fontFamily: "var(--font-mono)",
            }}
          >
            {val}%
          </div>
        </div>

        <div className="gauge-meta-list">
          <div className="gauge-meta-item">
            <span>{metaLeft?.label || "Primary"}</span>
            <strong>{metaLeft?.value ?? "—"}</strong>
          </div>
          <div className="gauge-meta-item">
            <span>{metaRight?.label || "Secondary"}</span>
            <strong>{metaRight?.value ?? "—"}</strong>
          </div>
        </div>
      </div>

      {actionLabel && (
        <button
          className="soc-btn"
          style={{ width: "100%", justifyContent: "center", marginTop: 4, fontSize: 11.5 }}
          onClick={onAction}
        >
          {actionLabel} →
        </button>
      )}
    </div>
  );
}

export default function App() {
  const [theme, setTheme] = useState(() => localStorage.getItem("sentryscan-theme") || "dark");
  const [route, setRoute] = useState(() => {
    if (window.location.pathname === "/master") return { page: "master" };
    return parseHashRoute(window.location.hash);
  });
  const [runs, setRuns] = useState([]);
  const [runId, setRunId] = useState("");
  const [wsConnected, setWsConnected] = useState(false);
  const [toast, setToast] = useState(null);

  // Core Data States
  const [overview, setOverview] = useState(null);
  const [assets, setAssets] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [incidents, setIncidents] = useState([]);
  const [radar, setRadar] = useState({ sources: [], findings: [], scans: [], policies: [] });
  const [pulse, setPulse] = useState({ controls: [], tasks: [], history: [], available_profiles: [] });
  const [remediations, setRemediations] = useState([]);
  const [reports, setReports] = useState([]);
  const [quarantines, setQuarantines] = useState([]);
  const [summary, setSummary] = useState({ events: 0, messages: 0, rejected: 0, findings: 0, quarantined: 0 });

  // POLARIS Staged Settings & Execution State
  const [stagedProfile, setStagedProfile] = useState("generic");
  const [stagedFramework, setStagedFramework] = useState("baseline");
  const [evaluatingPolaris, setEvaluatingPolaris] = useState(false);

  // SENTRA Scanning State
  const [scanningSentra, setScanningSentra] = useState(false);

  // Report Generation State
  const [reportWindow, setReportWindow] = useState("Last 30 Minutes");
  const [generatingReport, setGeneratingReport] = useState(false);
  const [expandedReportIdx, setExpandedReportIdx] = useState(0);
  const [pdfModalReport, setPdfModalReport] = useState(null);
  const [toolboxOpen, setToolboxOpen] = useState(false);
  const [reportTypeFilter, setReportTypeFilter] = useState("all");

  // Copilot Chat States
  const [copilotHistory, setCopilotHistory] = useState([
    {
      sender: "copilot",
      text: "SentryScan Autonomous Threat Copilot online. Click any pre-prompt chip above or type a question about quarantined hosts, CVEs, agent negotiation, SENTRA data exposures, or POLARIS compliance.",
      timestamp: new Date().toLocaleTimeString(),
    },
  ]);
  const [copilotInput, setCopilotInput] = useState("");
  const [copilotLoading, setCopilotLoading] = useState(false);

  // Filters
  const [alertSevFilter, setAlertSevFilter] = useState("");
  const [alertHostFilter, setAlertHostFilter] = useState("");
  const [assetTypeFilter, setAssetTypeFilter] = useState("");

  useEffect(() => {
    document.documentElement.setAttribute("data-theme", theme);
    localStorage.setItem("sentryscan-theme", theme);
  }, [theme]);

  useEffect(() => {
    const onHash = () => setRoute(parseHashRoute(window.location.hash));
    window.addEventListener("hashchange", onHash);
    return () => window.removeEventListener("hashchange", onHash);
  }, []);

  // Sync staged POLARIS settings with incoming backend state
  useEffect(() => {
    if (pulse.profile) setStagedProfile(pulse.profile);
    if (pulse.framework) setStagedFramework(pulse.framework);
  }, [pulse.profile, pulse.framework]);

  const navigate = useCallback((hash) => {
    if (window.location.pathname === "/master" && hash !== "#/master") {
      window.history.pushState({}, "", "/" + hash);
      setRoute(parseHashRoute(hash));
      return;
    }
    window.location.hash = hash;
  }, []);

  const showToast = useCallback((msg) => {
    setToast(msg);
    setTimeout(() => setToast(null), 3500);
  }, []);

  // Fetch runs list
  const fetchRuns = useCallback(async () => {
    try {
      const res = await fetch("/api/runs");
      if (!res.ok) return;
      const data = await res.json();
      const list = Array.isArray(data) ? data : data.runs || [];
      setRuns(list);
      if (list.length > 0 && !runId) {
        const liveItem = list.find((r) => (r.run_id || r) === "run-live") || list[0];
        setRunId(liveItem.run_id || liveItem);
      }
    } catch (_e) {}
  }, [runId]);

  useEffect(() => {
    fetchRuns();
  }, [fetchRuns]);

  // Load all run endpoints
  const loadRunAll = useCallback(async (targetRunId) => {
    if (!targetRunId) return;
    try {
      const [ovR, asR, alR, inR, raR, puR, reR, rpR, quR, suR] = await Promise.all([
        fetch(`/api/runs/${targetRunId}/overview`).then((r) => (r.ok ? r.json() : null)),
        fetch(`/api/runs/${targetRunId}/assets`).then((r) => (r.ok ? r.json() : [])),
        fetch(`/api/runs/${targetRunId}/alerts`).then((r) => (r.ok ? r.json() : [])),
        fetch(`/api/runs/${targetRunId}/incidents`).then((r) => (r.ok ? r.json() : [])),
        fetch(`/api/runs/${targetRunId}/radar`).then((r) => (r.ok ? r.json() : null)),
        fetch(`/api/runs/${targetRunId}/pulse`).then((r) => (r.ok ? r.json() : null)),
        fetch(`/api/runs/${targetRunId}/remediation`).then((r) => (r.ok ? r.json() : [])),
        fetch(`/api/runs/${targetRunId}/reports`).then((r) => (r.ok ? r.json() : null)),
        fetch(`/api/runs/${targetRunId}/quarantines`).then((r) => (r.ok ? r.json() : null)),
        fetch(`/api/runs/${targetRunId}/summary`).then((r) => (r.ok ? r.json() : null)),
      ]);

      if (ovR) setOverview(ovR);
      if (Array.isArray(asR)) setAssets(asR);
      if (Array.isArray(alR)) setAlerts(alR);
      if (Array.isArray(inR)) setIncidents(inR);
      if (raR) setRadar(raR);
      if (puR) setPulse(puR);
      if (Array.isArray(reR)) setRemediations(reR);
      if (rpR) setReports(Array.isArray(rpR) ? rpR : rpR.reports || []);
      if (quR) setQuarantines(Array.isArray(quR) ? quR : quR.quarantines || []);
      if (suR) setSummary(suR);
    } catch (_e) {}
  }, []);

  useEffect(() => {
    if (runId) {
      loadRunAll(runId);
    }
  }, [runId, loadRunAll]);

  // WebSocket Live Updates starting from seq 1 so telemetry stream immediately triggers updates
  useEffect(() => {
    if (!runId) return;
    const proto = window.location.protocol === "https:" ? "wss:" : "ws:";
    const wsUrl = `${proto}//${window.location.host}/ws/${runId}`;
    let ws;
    let pollTimer;
    try {
      ws = new WebSocket(wsUrl);
      ws.onopen = () => {
        setWsConnected(true);
        ws.send(JSON.stringify({ type: "subscribe", from_seq: 1 }));
      };
      ws.onclose = () => setWsConnected(false);
      ws.onmessage = () => {
        fetch(`/api/runs/${runId}/summary`)
          .then((r) => (r.ok ? r.json() : null))
          .then((s) => {
            if (s) setSummary(s);
          })
          .catch(() => {});
      };
    } catch (_e) {
      setWsConnected(false);
    }

    pollTimer = setInterval(() => {
      loadRunAll(runId);
    }, 4000);

    return () => {
      if (ws) ws.close();
      if (pollTimer) clearInterval(pollTimer);
    };
  }, [runId, loadRunAll]);

  // Copilot Ask Action
  const handleAskCopilot = async (questionText) => {
    const q = (questionText || copilotInput).trim();
    if (!q || !runId) return;

    setCopilotHistory((prev) => [
      ...prev,
      { sender: "user", text: q, timestamp: new Date().toLocaleTimeString() },
    ]);
    setCopilotInput("");
    setCopilotLoading(true);

    try {
      const res = await fetch(`/api/runs/${runId}/ask`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ question: q }),
      });
      if (res.ok) {
        const data = await res.json();
        setCopilotHistory((prev) => [
          ...prev,
          {
            sender: "copilot",
            text: data.answer || "No response received.",
            latency: data.latency_ms,
            model: data.model || "sentryscan-llm",
            timestamp: new Date().toLocaleTimeString(),
          },
        ]);
      }
    } catch (err) {
      setCopilotHistory((prev) => [
        ...prev,
        {
          sender: "copilot",
          text: `Error contacting Copilot: ${err.message}`,
          timestamp: new Date().toLocaleTimeString(),
        },
      ]);
    } finally {
      setCopilotLoading(false);
    }
  };

  // Generate 30-Min / On-Demand Posture Report
  const handleGenerateReport = async () => {
    if (!runId || generatingReport) return;
    setGeneratingReport(true);
    try {
      const res = await fetch(`/api/runs/${runId}/reports/generate`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ window_name: reportWindow }),
      });
      if (res.ok) {
        const rep = await res.json();
        setReports((prev) => [rep, ...prev]);
        setExpandedReportIdx(0);
        showToast(`Generated Posture Report (${reportWindow}) — Score: ${rep.posture_score}/100`);
      }
    } catch (_e) {}
    setGeneratingReport(false);
  };

  // Quarantine Approve / Reject
  const handleQuarantineDecide = async (quarantineId, decision) => {
    if (!runId) return;
    const res = await fetch(`/api/runs/${runId}/quarantines/${quarantineId}/decide`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ decision, decided_by: "console-operator" }),
    });
    if (res.ok) {
      showToast(`Quarantine ${quarantineId} marked ${decision}.`);
      loadRunAll(runId);
    }
  };

  // Run SENTRA Discovery Scan with clear button feedback
  const handleTriggerSentraScan = async () => {
    if (!runId || scanningSentra) return;
    setScanningSentra(true);
    try {
      const res = await fetch(`/api/runs/${runId}/radar/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({}),
      });
      if (res.ok) {
        showToast("SENTRA Discovery Scan executed across enterprise data sources.");
        await loadRunAll(runId);
      }
    } catch (_e) {}
    setScanningSentra(false);
  };

  // Apply & Evaluate POLARIS Controls with explicit button action
  const handleApplyPolarisSettings = async () => {
    if (!runId || evaluatingPolaris) return;
    setEvaluatingPolaris(true);
    try {
      const res = await fetch(`/api/runs/${runId}/pulse/settings`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ profile: stagedProfile, framework: stagedFramework }),
      });
      if (res.ok) {
        showToast(`POLARIS compliance evaluated: ${stagedProfile.toUpperCase()} / ${stagedFramework.toUpperCase()}`);
        await loadRunAll(runId);
      }
    } catch (_e) {}
    setEvaluatingPolaris(false);
  };

  // Return Full-Screen Master Cyber Console when requested via `/master` or `#/master`
  if (route.page === "master") {
    return <MasterCyberConsole runId={runId} onBack={() => navigate("#/overview")} />;
  }

  // Filtered views
  const filteredAlerts = alerts.filter((a) => {
    if (alertSevFilter && (a.severity || "").toLowerCase() !== alertSevFilter.toLowerCase())
      return false;
    if (alertHostFilter && !(a.host_id || "").toLowerCase().includes(alertHostFilter.toLowerCase()))
      return false;
    return true;
  });

  const filteredAssets = assets.filter((a) => {
    if (assetTypeFilter && a.asset_type !== assetTypeFilter) return false;
    return true;
  });

  return (
    <div className="soc-shell">
      {/* 1. LEFT SIDEBAR NAVIGATION */}
      <aside className="soc-sidebar">
        <div className="soc-brand">
          <div className="soc-brand-icon">●</div>
          <div>
            <div className="soc-brand-title">SentryScan</div>
            <div className="soc-brand-sub">VIGIL · SENTRA · POLARIS</div>
          </div>
        </div>

        <nav className="soc-nav">
          <div className="soc-nav-heading">Master Agent Console</div>
          <a
            href="#/master"
            className="soc-nav-item master-item"
            title="Open full-screen original SentryScan Master Agent Console"
          >
            <span>▶ Master Cyber Console</span>
            <span
              className="soc-nav-badge"
              style={{ background: "#5dff9d", color: "#051209", fontWeight: 700 }}
            >
              /master
            </span>
          </a>

          <button
            type="button"
            className="soc-nav-item"
            style={{ border: "none", background: "none", width: "100%", textAlign: "left", cursor: "pointer", display: "flex", justifyContent: "space-between", alignItems: "center" }}
            onClick={() => setToolboxOpen(true)}
            title="Open Interactive Threat Injection & Simulation Toolbox"
          >
            <span>⚡ Threat Toolbox</span>
            <span
              className="soc-nav-badge"
              style={{ background: "#4da3ff", color: "#041221", fontWeight: 700 }}
            >
              INJECT
            </span>
          </button>

          <div className="soc-nav-heading">Command &amp; Intelligence</div>
          <a
            href="#/overview"
            className={`soc-nav-item ${route.page === "overview" ? "active" : ""}`}
          >
            <span>Executive Overview</span>
            <span className="soc-nav-badge">{overview?.security_score ?? 85}%</span>
          </a>

          <a
            href="#/copilot"
            className={`soc-nav-item copilot-item ${route.page === "copilot" ? "active" : ""}`}
          >
            <span>SOC Copilot &amp; Reports</span>
            <span
              className="soc-nav-badge"
              style={{ background: "#4da3ff", color: "#041221", fontWeight: 700 }}
            >
              AI
            </span>
          </a>

          <a
            href="#/agents"
            className={`soc-nav-item ${route.page === "agents" ? "active" : ""}`}
          >
            <span>Live Agent Operations</span>
            <span className="soc-nav-badge">{summary.messages}</span>
          </a>

          <div className="soc-nav-heading">Core Modules</div>
          <a
            href="#/vigil"
            className={`soc-nav-item ${route.page === "vigil" ? "active" : ""}`}
          >
            <span>VIGIL · Agentic SOC</span>
            <span className="soc-nav-badge crit">{incidents.length}</span>
          </a>

          <a
            href="#/sentra"
            className={`soc-nav-item ${route.page === "sentra" ? "active" : ""}`}
          >
            <span>SENTRA · Data Discovery</span>
            <span className="soc-nav-badge">{radar.findings?.length || 0}</span>
          </a>

          <a
            href="#/polaris"
            className={`soc-nav-item ${route.page === "polaris" ? "active" : ""}`}
          >
            <span>POLARIS · Compliance</span>
            <span className="soc-nav-badge">{pulse.score ?? 80}%</span>
          </a>

          <div className="soc-nav-heading">Enterprise Fleet</div>
          <a
            href="#/assets"
            className={`soc-nav-item ${route.page === "assets" ? "active" : ""}`}
          >
            <span>Asset Inventory</span>
            <span className="soc-nav-badge">{assets.length || 100}</span>
          </a>
        </nav>

        <div className="soc-sidebar-footer">
          <div style={{ display: "flex", justifyContent: "space-between" }}>
            <span>POLARIS Profile:</span>
            <strong className="mono" style={{ color: "var(--accent-cyan)" }}>
              {(pulse.profile || "generic").toUpperCase()}
            </strong>
          </div>
          <div style={{ display: "flex", justifyContent: "space-between" }}>
            <span>Framework:</span>
            <strong className="mono" style={{ color: "var(--status-pass)" }}>
              {(pulse.framework || "baseline").toUpperCase()}
            </strong>
          </div>
        </div>
      </aside>

      {/* 2. MAIN WORKSPACE VIEWPORT */}
      <div className="soc-main">
        {/* TOPBAR */}
        <header className="soc-header">
          <div className="soc-header-left">
            <span style={{ fontSize: 11.5, color: "var(--text-muted)", fontWeight: 600 }}>
              RUN:
            </span>
            <select
              className="soc-select"
              value={runId}
              onChange={(e) => setRunId(e.target.value)}
            >
              {runs.map((r) => {
                const rid = r.run_id || r;
                return (
                  <option key={rid} value={rid}>
                    {rid}
                  </option>
                );
              })}
            </select>

            <span
              className="soc-badge-sim"
              title="All telemetry and sensitive data in this fleet are synthetic."
            >
              <span>◆</span> SIMULATED FLEET ({assets.length || 100} DEVICES)
            </span>

            <span className={`soc-pill ${wsConnected ? "pass" : "neutral"}`}>
              <span>●</span> {wsConnected ? "LIVE STREAM" : "REPLAY"}
            </span>
          </div>

          <div className="soc-header-right">
            <button
              className="soc-btn"
              style={{ background: "rgba(77, 163, 255, 0.15)", color: "#4da3ff", borderColor: "#4da3ff", fontWeight: 700 }}
              onClick={() => setToolboxOpen(true)}
              title="Open Simulation Control & Threat Injection Toolbox"
            >
              ⚡ Threat Toolbox
            </button>

            <a href="#/master" className="soc-btn soc-btn-primary">
              <span>▶</span> Open /master Console
            </a>

            <button className="soc-btn" onClick={() => navigate("#/copilot")}>
              Copilot &amp; 30m Reports
            </button>

            <button
              className="soc-btn"
              onClick={() => setTheme(theme === "dark" ? "light" : "dark")}
            >
              {theme === "dark" ? "☀ Light Mode" : "☾ Dark Mode"}
            </button>
          </div>
        </header>

        {/* TOAST ALERT */}
        {toast && (
          <div className="soc-toast">
            <span>{toast}</span>
            <button onClick={() => setToast(null)}>✕</button>
          </div>
        )}

        {/* PAGE CONTENT ROUTER */}
        <main
          className="soc-content"
          style={route.page === "agents" ? { padding: 0, overflow: "hidden" } : undefined}
        >
          {/* ==============================================================
              PAGE 1: DEDICATED SOC COPILOT & 30-MINUTE REPORTS TAB (#/copilot)
             ============================================================== */}
          {route.page === "copilot" && (
            <div>
              <div className="soc-page-header">
                <div>
                  <h1 className="soc-page-title">
                    Autonomous SOC Threat Copilot &amp; 30-Minute Posture Reports
                  </h1>
                  <div className="soc-page-sub">
                    Interactive pre-prompts, grounded SQLite telemetry Q&amp;A, and scheduled 30-minute / on-demand executive reports
                  </div>
                </div>
                <button className="soc-btn" onClick={() => navigate("#/master")}>
                  Open in /master Console →
                </button>
              </div>

              <div className="soc-grid-2">
                {/* LEFT: COPILOT WITH PRE-PROMPT CHIPS */}
                <div className="copilot-workspace">
                  <div
                    style={{
                      padding: "12px 16px",
                      borderBottom: "1px solid var(--border-subtle)",
                    }}
                  >
                    <div
                      style={{
                        fontSize: 11,
                        textTransform: "uppercase",
                        letterSpacing: "0.08em",
                        color: "var(--text-muted)",
                        marginBottom: 8,
                      }}
                    >
                      Quick Investigation Pre-Prompts (Click to Ask)
                    </div>
                    <div className="mc-chips">
                      {COPILOT_PROMPTS.map((chip) => (
                        <span
                          key={chip}
                          className="mc-chip"
                          onClick={() => handleAskCopilot(chip)}
                        >
                          {chip}
                        </span>
                      ))}
                    </div>
                  </div>

                  <div className="copilot-thread">
                    {copilotHistory.map((item, idx) => (
                      <div
                        key={idx}
                        className={
                          item.sender === "user"
                            ? "copilot-msg-user"
                            : "copilot-msg-assistant"
                        }
                      >
                        <div
                          style={{
                            fontSize: 11,
                            opacity: 0.75,
                            marginBottom: 4,
                          }}
                        >
                          {item.sender === "user" ? "Analyst" : "SentryScan Copilot"} ·{" "}
                          {item.timestamp}
                          {item.latency ? ` · ${item.latency}ms` : ""}
                        </div>
                        <div style={{ whiteSpace: "pre-wrap", lineHeight: 1.6 }}>
                          {item.text}
                        </div>
                      </div>
                    ))}
                    {copilotLoading && (
                      <div className="copilot-msg-assistant" style={{ opacity: 0.7 }}>
                        Querying SQLite telemetry, Contract-Net messages, and BDI states...
                      </div>
                    )}
                  </div>

                  <div className="copilot-input-bar">
                    <input
                      type="text"
                      className="soc-input"
                      style={{ flex: 1 }}
                      placeholder="Ask Copilot about quarantined hosts, critical CVEs, or agent negotiation..."
                      value={copilotInput}
                      onChange={(e) => setCopilotInput(e.target.value)}
                      onKeyDown={(e) => {
                        if (e.key === "Enter") handleAskCopilot();
                      }}
                    />
                    <button
                      className="soc-btn soc-btn-primary"
                      onClick={() => handleAskCopilot()}
                    >
                      Ask Copilot →
                    </button>
                  </div>
                </div>

                {/* RIGHT: 30-MINUTE & ON-DEMAND POSTURE REPORT GENERATOR */}
                <div
                  className="soc-card"
                  style={{
                    display: "flex",
                    flexDirection: "column",
                    height: "calc(100vh - 175px)",
                  }}
                >
                  <div className="soc-card-header">
                    <div>
                      <div className="soc-card-title">
                        30-Minute &amp; On-Demand Posture Reports
                      </div>
                      <div style={{ fontSize: 11, color: "var(--text-muted)" }}>
                        Auto-generates every 30 minutes in live mode or generate on-demand for any window
                      </div>
                    </div>
                  </div>

                  <div className="mc-rep-ctrl" style={{ marginBottom: 14 }}>
                    <select
                      className="soc-select"
                      style={{ flex: 1 }}
                      value={reportWindow}
                      onChange={(e) => setReportWindow(e.target.value)}
                    >
                      {REPORT_WINDOWS.map((w) => (
                        <option key={w} value={w}>
                          {w}
                        </option>
                      ))}
                    </select>
                    <button
                      className="soc-btn soc-btn-primary"
                      disabled={generatingReport}
                      onClick={handleGenerateReport}
                    >
                      {generatingReport ? "Generating..." : "Generate Report"}
                    </button>
                  </div>

                  {/* Filter Tabs for Reports vs Remediation Plans */}
                  <div style={{ display: "flex", gap: 6, marginBottom: 8, flexWrap: "wrap" }}>
                    <button
                      className={`soc-btn ${reportTypeFilter === "all" ? "soc-btn-primary" : ""}`}
                      style={{ fontSize: 11, padding: "3px 8px" }}
                      onClick={() => setReportTypeFilter("all")}
                    >
                      All ({reports.length})
                    </button>
                    <button
                      className={`soc-btn ${reportTypeFilter === "posture" ? "soc-btn-primary" : ""}`}
                      style={{ fontSize: 11, padding: "3px 8px" }}
                      onClick={() => setReportTypeFilter("posture")}
                    >
                      30m Posture ({reports.filter((r) => r.data?.type !== "remediation_plan" && !r.report_id?.startsWith("remed-")).length})
                    </button>
                    <button
                      className={`soc-btn ${reportTypeFilter === "remediation" ? "soc-btn-primary" : ""}`}
                      style={{ fontSize: 11, padding: "3px 8px" }}
                      onClick={() => setReportTypeFilter("remediation")}
                    >
                      Remediation Plans ({reports.filter((r) => r.data?.type === "remediation_plan" || r.report_id?.startsWith("remed-")).length})
                    </button>
                  </div>
                  <div style={{ fontSize: 11, color: "var(--text-muted)", marginBottom: 10, lineHeight: 1.4 }}>
                    ℹ️ <b>Scheduled Posture Reports</b> auto-generate every 30 minutes. <b>Remediation Plans</b> auto-generate dry-run containment rules per quarantined host.
                  </div>

                  <div style={{ flex: 1, overflowY: "auto", paddingRight: 4 }}>
                    {(() => {
                      const isRemed = (r) => (
                        r.data?.type === "remediation_plan" ||
                        r.report_id?.startsWith("remed-") ||
                        r.window_name?.startsWith("Remediation Plan")
                      );
                      const displayReports = reports.filter((r) => {
                        if (reportTypeFilter === "posture") return !isRemed(r);
                        if (reportTypeFilter === "remediation") return isRemed(r);
                        return true;
                      });

                      if (displayReports.length === 0) {
                        return (
                          <div className="mc-empty">
                            No reports matching filter &quot;{reportTypeFilter}&quot;.
                          </div>
                        );
                      }

                      return displayReports.map((r, idx) => {
                        const isRem = isRemed(r);
                        return (
                          <div
                            key={r.report_id || idx}
                            className="mc-card"
                            style={{ marginBottom: 10 }}
                          >
                            <div
                              style={{
                                display: "flex",
                                justifyContent: "space-between",
                                alignItems: "center",
                                marginBottom: 6,
                              }}
                            >
                              <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                                <span
                                  className="mc-tag"
                                  style={{
                                    color: isRem ? "#ff9a3c" : "#4da3ff",
                                    border: `1px solid ${isRem ? "#ff9a3c" : "#4da3ff"}`,
                                    fontSize: 9.5,
                                  }}
                                >
                                  {isRem ? "HOST REMEDIATION" : "30-MIN POSTURE"}
                                </span>
                                <b>{r.window_name}</b>
                              </div>
                              <span
                                className={`mc-score-badge ${r.threat_level || "NOMINAL"}`}
                              >
                                {r.threat_level} · Score: {r.posture_score}/100
                              </span>
                            </div>
                            <div
                              className="mc-muted"
                              style={{ fontSize: 10.5, marginBottom: 8 }}
                            >
                              {r.created_at} · ID: <code>{r.report_id}</code>
                            </div>
                            {isRem && (
                              <pre className="mc-pre" style={{ marginBottom: 8 }}>
                                {`${r.data?.iptables || ""}\n\n${r.data?.nftables || ""}`}
                              </pre>
                            )}
                          {(() => {
                            const targetRun = r.run_id || runId || "run-live";
                            const pdfUrl = `/api/runs/${encodeURIComponent(targetRun)}/reports/${encodeURIComponent(r.report_id)}/pdf`;
                            const filename = `${r.report_id || "posture-report"}.pdf`;
                            return (
                              <div style={{ display: "flex", gap: 6, flexWrap: "wrap", marginBottom: 6 }}>
                                <button
                                  className="soc-btn"
                                  style={{ fontSize: 11, padding: "4px 8px" }}
                                  onClick={() =>
                                    setExpandedReportIdx(
                                      expandedReportIdx === idx ? null : idx
                                    )
                                  }
                                >
                                  {expandedReportIdx === idx
                                    ? "Hide Document ▲"
                                    : "View Text Document ▼"}
                                </button>
                                <button
                                  className="soc-btn soc-btn-primary"
                                  style={{ fontSize: 11, padding: "4px 10px" }}
                                  onClick={() => setPdfModalReport(r)}
                                  title="Open live in-browser PDF previewer"
                                >
                                  <span>📄</span> View PDF (Preview)
                                </button>
                                <a
                                  className="soc-btn"
                                  href={pdfUrl}
                                  download={filename}
                                  style={{
                                    fontSize: 11,
                                    padding: "4px 8px",
                                    textDecoration: "none",
                                    display: "inline-flex",
                                    alignItems: "center",
                                    gap: 3,
                                  }}
                                  title="Download PDF directly to your device"
                                >
                                  <span>⬇</span> Download
                                </a>
                                <a
                                  className="soc-btn"
                                  href={pdfUrl}
                                  target="_blank"
                                  rel="noopener noreferrer"
                                  style={{
                                    fontSize: 11,
                                    padding: "4px 8px",
                                    textDecoration: "none",
                                    display: "inline-flex",
                                    alignItems: "center",
                                    gap: 3,
                                  }}
                                  title="Open PDF in a new browser tab"
                                >
                                  <span>⤢</span> Tab
                                </a>
                              </div>
                            );
                          })()}
                          {expandedReportIdx === idx && (
                            <div
                              className="mc-rep-doc"
                              style={{ whiteSpace: "pre-wrap" }}
                            >
                              {r.summary_md}
                            </div>
                          )}
                        </div>
                      );
                    });
                  })()}
                </div>
                </div>
              </div>
            </div>
          )}

          {/* ==============================================================
              PAGE 2: EXECUTIVE POSTURE OVERVIEW (#/overview)
             ============================================================== */}
          {route.page === "overview" && (
            <div>
              <div className="soc-page-header">
                <div>
                  <h1 className="soc-page-title">
                    Executive Security, Data &amp; Compliance Overview
                  </h1>
                  <div className="soc-page-sub">
                    Unified defense across VIGIL (Agentic SOC), SENTRA (Sensitive Data Discovery), and POLARIS (Continuous Compliance)
                  </div>
                </div>
                <div style={{ display: "flex", gap: 8 }}>
                  <button className="soc-btn" onClick={() => navigate("#/copilot")}>
                    30m Posture Reports ({reports.length})
                  </button>
                  <button
                    className="soc-btn soc-btn-primary"
                    disabled={scanningSentra}
                    onClick={handleTriggerSentraScan}
                  >
                    {scanningSentra ? "Scanning..." : "Run SENTRA Discovery Scan"}
                  </button>
                </div>
              </div>

              {/* 4 Clean Posture Ring Gauges */}
              <div className="soc-gauge-grid">
                <RingGaugeCard
                  title="Security Posture Index"
                  subtitle="VIGIL Agentic SOC"
                  score={overview?.security_score ?? 85}
                  status={
                    overview?.incidents?.contained > 0
                      ? "CONTAINMENT ACTIVE"
                      : "NOMINAL"
                  }
                  metaLeft={{
                    label: "Active Cases",
                    value: overview?.incidents?.active ?? incidents.length,
                  }}
                  metaRight={{
                    label: "Total Detections",
                    value: summary.findings,
                  }}
                  actionLabel="Open VIGIL Workspace"
                  onAction={() => navigate("#/vigil")}
                />

                <RingGaugeCard
                  title="Compliance Index"
                  subtitle={`POLARIS · ${(pulse.framework || "baseline").toUpperCase()}`}
                  score={pulse.score ?? 80}
                  status={pulse.score >= 80 ? "PASS" : "ATTENTION"}
                  metaLeft={{
                    label: "Controls Evaluated",
                    value: pulse.controls?.length || 8,
                  }}
                  metaRight={{
                    label: "Open Remediations",
                    value: overview?.remediation?.open ?? remediations.length,
                  }}
                  actionLabel="Inspect POLARIS Controls"
                  onAction={() => navigate("#/polaris")}
                />

                <RingGaugeCard
                  title="Data Exposure Posture"
                  subtitle="SENTRA Classification Engine"
                  score={
                    overview?.exposure?.findings
                      ? Math.max(10, 100 - overview.exposure.public * 2)
                      : 90
                  }
                  status={overview?.exposure?.public > 0 ? "AT RISK" : "PASS"}
                  metaLeft={{
                    label: "Public Exposures",
                    value: overview?.exposure?.public ?? 0,
                  }}
                  metaRight={{
                    label: "Sensitive Artifacts",
                    value: overview?.exposure?.findings ?? radar.findings?.length,
                  }}
                  actionLabel="Explore SENTRA Findings"
                  onAction={() => navigate("#/sentra")}
                />

                <RingGaugeCard
                  title="Live Agent Telemetry"
                  subtitle="11 Autonomous Agents"
                  score={overview?.evidence_freshness ?? 100}
                  status="PASS"
                  metaLeft={{ label: "Events Streamed", value: summary.events }}
                  metaRight={{ label: "Agent Messages", value: summary.messages }}
                  actionLabel="Open Live Agent Network"
                  onAction={() => navigate("#/agents")}
                />
              </div>

              {/* Active Incidents & Quick 30-Min Report Generator */}
              <div className="soc-grid-2">
                <div className="soc-card">
                  <div className="soc-card-header">
                    <div className="soc-card-title">
                      Escalated Security Incidents ({incidents.length})
                    </div>
                    <button className="soc-btn" onClick={() => navigate("#/vigil")}>
                      View All
                    </button>
                  </div>
                  <div className="soc-table-wrap">
                    <table className="soc-table">
                      <thead>
                        <tr>
                          <th>Incident ID</th>
                          <th>Severity</th>
                          <th>Target Asset</th>
                          <th>Status</th>
                        </tr>
                      </thead>
                      <tbody>
                        {incidents.slice(0, 6).map((inc) => (
                          <tr
                            key={inc.incident_id}
                            className="clickable"
                            onClick={() => navigate("#/vigil")}
                          >
                            <td
                              className="mono"
                              style={{
                                color: "var(--accent-cyan)",
                                fontWeight: 700,
                              }}
                            >
                              {inc.incident_id}
                            </td>
                            <td>
                              <StatusPill
                                level={inc.severity}
                                label={inc.severity}
                              />
                            </td>
                            <td className="mono">{inc.host_id}</td>
                            <td>
                              <StatusPill level={inc.status} label={inc.status} />
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>

                <div className="soc-card">
                  <div className="soc-card-header">
                    <div className="soc-card-title">
                      30-Minute Posture Report &amp; Copilot Quick Actions
                    </div>
                    <button className="soc-btn" onClick={() => navigate("#/copilot")}>
                      Open Full Copilot
                    </button>
                  </div>

                  <div className="mc-rep-ctrl" style={{ marginBottom: 12 }}>
                    <select
                      className="soc-select"
                      style={{ flex: 1 }}
                      value={reportWindow}
                      onChange={(e) => setReportWindow(e.target.value)}
                    >
                      {REPORT_WINDOWS.map((w) => (
                        <option key={w} value={w}>
                          {w}
                        </option>
                      ))}
                    </select>
                    <button
                      className="soc-btn soc-btn-primary"
                      disabled={generatingReport}
                      onClick={handleGenerateReport}
                    >
                      {generatingReport ? "Generating..." : "Generate 30m Report"}
                    </button>
                  </div>

                  <div
                    style={{
                      fontSize: 11,
                      color: "var(--text-muted)",
                      marginBottom: 6,
                    }}
                  >
                    Click a pre-prompt to ask SOC Copilot:
                  </div>
                  <div className="mc-chips">
                    {COPILOT_PROMPTS.map((chip) => (
                      <span
                        key={chip}
                        className="mc-chip"
                        onClick={() => {
                          navigate("#/copilot");
                          handleAskCopilot(chip);
                        }}
                      >
                        {chip}
                      </span>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* ==============================================================
              PAGE 3: VIGIL WORKSPACE (#/vigil)
             ============================================================== */}
          {route.page === "vigil" && (
            <div>
              <div className="soc-page-header">
                <div>
                  <h1 className="soc-page-title">
                    VIGIL · Autonomous SOC &amp; Incident Queue
                  </h1>
                  <div className="soc-page-sub">
                    Multi-host attack correlation, L3 quarantine approval gates, and automated anomaly investigations
                  </div>
                </div>
                <button
                  className="soc-btn soc-btn-primary"
                  onClick={() => navigate("#/master")}
                >
                  Open /master Terminal View
                </button>
              </div>

              {/* Pending L3 Quarantine Approvals */}
              {quarantines.filter((q) => q.status === "PENDING").length > 0 && (
                <div
                  className="soc-card"
                  style={{
                    marginBottom: 20,
                    borderLeft: "3px solid var(--sev-high)",
                  }}
                >
                  <div className="soc-card-header">
                    <div
                      className="soc-card-title"
                      style={{ color: "var(--sev-high)" }}
                    >
                      Pending L3 Containment Quarantine Approvals (
                      {quarantines.filter((q) => q.status === "PENDING").length})
                    </div>
                  </div>
                  <div style={{ display: "grid", gap: 10 }}>
                    {quarantines
                      .filter((q) => q.status === "PENDING")
                      .map((q) => (
                        <div
                          key={q.quarantine_id}
                          className="mc-card"
                          style={{
                            display: "flex",
                            justifyContent: "space-between",
                            alignItems: "center",
                          }}
                        >
                          <div>
                            <b className="mono">{q.host_id}</b> ·{" "}
                            <code>{q.rule_id}</code>
                            <div className="mc-muted">
                              Confidence: {q.confidence} · Remote Exploitable:{" "}
                              {q.remote_exploitable ? "YES" : "NO"} · Finding:{" "}
                              {q.finding_id}
                            </div>
                          </div>
                          <div style={{ display: "flex", gap: 8 }}>
                            <button
                              className="soc-btn soc-btn-primary"
                              onClick={() =>
                                handleQuarantineDecide(
                                  q.quarantine_id,
                                  "APPROVED"
                                )
                              }
                            >
                              Approve Quarantine
                            </button>
                            <button
                              className="soc-btn"
                              onClick={() =>
                                handleQuarantineDecide(
                                  q.quarantine_id,
                                  "REJECTED"
                                )
                              }
                            >
                              Reject
                            </button>
                          </div>
                        </div>
                      ))}
                  </div>
                </div>
              )}

              {/* Incidents Table */}
              <div className="soc-card" style={{ marginBottom: 20 }}>
                <div className="soc-card-header">
                  <div className="soc-card-title">
                    Correlated Threat Cases ({incidents.length})
                  </div>
                  <span className="soc-pill high">{incidents.length} CASES</span>
                </div>
                <div className="soc-table-wrap">
                  <table className="soc-table">
                    <thead>
                      <tr>
                        <th>Incident ID</th>
                        <th>Severity</th>
                        <th>Affected Host</th>
                        <th>Summary</th>
                        <th>Status</th>
                        <th>Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {incidents.map((inc) => (
                        <tr key={inc.incident_id}>
                          <td
                            className="mono"
                            style={{
                              fontWeight: 700,
                              color: "var(--accent-cyan)",
                            }}
                          >
                            {inc.incident_id}
                          </td>
                          <td>
                            <StatusPill
                              level={inc.severity}
                              label={inc.severity}
                            />
                          </td>
                          <td className="mono">{inc.host_id}</td>
                          <td>{inc.title || inc.summary}</td>
                          <td>
                            <StatusPill level={inc.status} label={inc.status} />
                          </td>
                          <td>
                            <button
                              className="soc-btn"
                              onClick={() => navigate("#/agents")}
                            >
                              Inspect Agent Trace →
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>

              {/* Alert Detections Queue */}
              <div className="soc-card">
                <div className="soc-card-header">
                  <div className="soc-card-title">
                    Security Alert Stream ({filteredAlerts.length})
                  </div>
                  <div style={{ display: "flex", gap: 8 }}>
                    <select
                      className="soc-select"
                      value={alertSevFilter}
                      onChange={(e) => setAlertSevFilter(e.target.value)}
                    >
                      <option value="">All Severities</option>
                      <option value="CRITICAL">Critical</option>
                      <option value="HIGH">High</option>
                      <option value="MEDIUM">Medium</option>
                      <option value="LOW">Low</option>
                    </select>
                    <input
                      type="text"
                      className="soc-input"
                      placeholder="Filter host..."
                      value={alertHostFilter}
                      onChange={(e) => setAlertHostFilter(e.target.value)}
                    />
                  </div>
                </div>
                <div className="soc-table-wrap">
                  <table className="soc-table">
                    <thead>
                      <tr>
                        <th>Finding ID</th>
                        <th>Severity</th>
                        <th>Host ID</th>
                        <th>Rule ID</th>
                        <th>Evidence / Description</th>
                        <th>Quarantined</th>
                      </tr>
                    </thead>
                    <tbody>
                      {filteredAlerts.map((a) => (
                        <tr key={a.finding_id}>
                          <td className="mono">{a.finding_id}</td>
                          <td>
                            <StatusPill level={a.severity} label={a.severity} />
                          </td>
                          <td className="mono">{a.host_id}</td>
                          <td className="mono">{a.rule_id}</td>
                          <td>{a.title || a.description}</td>
                          <td>
                            <StatusPill
                              level={a.quarantined ? "critical" : "pass"}
                              label={a.quarantined ? "QUARANTINED" : "NOMINAL"}
                            />
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}

          {/* ==============================================================
              PAGE 4: SENTRA WORKSPACE (#/sentra)
             ============================================================== */}
          {route.page === "sentra" && (
            <div>
              <div className="soc-page-header">
                <div>
                  <h1 className="soc-page-title">
                    SENTRA · Configurable Sensitive Data Discovery
                  </h1>
                  <div className="soc-page-sub">
                    Industry-agnostic regex and keyword data classification across endpoints, servers, databases, and cloud stores
                  </div>
                </div>
                <button
                  className="soc-btn soc-btn-primary"
                  disabled={scanningSentra}
                  onClick={handleTriggerSentraScan}
                >
                  {scanningSentra ? "Scanning Data Sources..." : "Run SENTRA Discovery Scan"}
                </button>
              </div>

              <div className="soc-card" style={{ marginBottom: 20 }}>
                <div className="soc-card-header">
                  <div className="soc-card-title">
                    Classified Sensitive Data Findings ({radar.findings?.length || 0})
                  </div>
                </div>
                <div className="soc-table-wrap">
                  <table className="soc-table">
                    <thead>
                      <tr>
                        <th>Finding ID</th>
                        <th>Category</th>
                        <th>Sensitivity</th>
                        <th>Asset Host</th>
                        <th>Exposure Status</th>
                        <th>Encrypted</th>
                        <th>Redacted Sample</th>
                      </tr>
                    </thead>
                    <tbody>
                      {(radar.findings || []).map((f) => (
                        <tr key={f.finding_id}>
                          <td className="mono">{f.finding_id}</td>
                          <td>
                            <span className="soc-pill info">
                              {f.category_label || f.category}
                            </span>
                          </td>
                          <td>
                            <StatusPill
                              level={f.sensitivity}
                              label={f.sensitivity}
                            />
                          </td>
                          <td className="mono">{f.host_id}</td>
                          <td>
                            <StatusPill
                              level={
                                f.exposure_status === "internal_restricted"
                                  ? "pass"
                                  : "critical"
                              }
                              label={f.exposure_status}
                            />
                          </td>
                          <td>
                            <StatusPill
                              level={f.encrypted ? "pass" : "critical"}
                              label={f.encrypted ? "YES" : "NO"}
                            />
                          </td>
                          <td className="mono" style={{ fontSize: 11.5 }}>
                            {f.sample_redacted}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}

          {/* ==============================================================
              PAGE 5: POLARIS WORKSPACE (#/polaris)
             ============================================================== */}
          {route.page === "polaris" && (
            <div>
              <div className="soc-page-header">
                <div>
                  <h1 className="soc-page-title">
                    POLARIS · Continuous Compliance &amp; Control Registry
                  </h1>
                  <div className="soc-page-sub">
                    Automated security framework mappings backed by continuous VIGIL and SENTRA telemetry evidence
                  </div>
                </div>
                <div style={{ display: "flex", gap: 10, alignItems: "center", flexWrap: "wrap" }}>
                  <select
                    className="soc-select"
                    value={stagedProfile}
                    onChange={(e) => setStagedProfile(e.target.value)}
                  >
                    {(pulse.available_profiles || ["generic", "healthcare"]).map((p) => (
                      <option key={p} value={p}>
                        {p.toUpperCase()}
                      </option>
                    ))}
                  </select>
                  <select
                    className="soc-select"
                    value={stagedFramework}
                    onChange={(e) => setStagedFramework(e.target.value)}
                  >
                    <option value="baseline">Baseline-8</option>
                    <option value="iso27001">ISO/IEC 27001:2022</option>
                    <option value="nistcsf">NIST CSF 2.0</option>
                  </select>
                  <button
                    className="soc-btn soc-btn-primary"
                    disabled={evaluatingPolaris}
                    onClick={handleApplyPolarisSettings}
                  >
                    {evaluatingPolaris ? "Evaluating Controls..." : "Apply & Evaluate POLARIS Controls"}
                  </button>
                </div>
              </div>

              <div className="soc-card" style={{ marginBottom: 20 }}>
                <div className="soc-card-header">
                  <div className="soc-card-title">
                    Evaluated Controls ({pulse.controls?.length || 0})
                  </div>
                  <span className="mono" style={{ fontWeight: 700 }}>
                    Compliance Score: {pulse.score ?? 80}%
                  </span>
                </div>
                <div className="soc-table-wrap">
                  <table className="soc-table">
                    <thead>
                      <tr>
                        <th>Control ID</th>
                        <th>Framework Ref</th>
                        <th>Requirement</th>
                        <th>Status</th>
                        <th>Evidence Freshness</th>
                        <th>Affected Hosts</th>
                      </tr>
                    </thead>
                    <tbody>
                      {(pulse.controls || []).map((c) => (
                        <tr key={c.id}>
                          <td className="mono" style={{ fontWeight: 700 }}>
                            {c.id}
                          </td>
                          <td className="mono">{c.framework_ref}</td>
                          <td>{c.title}</td>
                          <td>
                            <StatusPill level={c.status} label={c.status} />
                          </td>
                          <td className="mono">100%</td>
                          <td className="mono">{c.affected_hosts?.length || 0} assets</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}

          {/* ==============================================================
              PAGE 6: ASSETS INVENTORY (#/assets)
             ============================================================== */}
          {route.page === "assets" && (
            <div>
              <div className="soc-page-header">
                <div>
                  <h1 className="soc-page-title">
                    Enterprise Asset Inventory ({assets.length || 100} Devices)
                  </h1>
                  <div className="soc-page-sub">
                    11-class heterogeneous fleet: Windows, Linux, Cisco Routers, Firewalls, AWS, Azure, M365, Databases &amp; IoT
                  </div>
                </div>
                <select
                  className="soc-select"
                  value={assetTypeFilter}
                  onChange={(e) => setAssetTypeFilter(e.target.value)}
                >
                  <option value="">All Asset Types</option>
                  {Array.from(new Set(assets.map((a) => a.asset_type))).map((t) => (
                    <option key={t} value={t}>
                      {t}
                    </option>
                  ))}
                </select>
              </div>

              <div className="soc-card">
                <div className="soc-table-wrap">
                  <table className="soc-table">
                    <thead>
                      <tr>
                        <th>Host ID</th>
                        <th>Asset Type</th>
                        <th>Category</th>
                        <th>OS / Platform</th>
                        <th>Criticality</th>
                        <th>Status</th>
                      </tr>
                    </thead>
                    <tbody>
                      {filteredAssets.map((a) => (
                        <tr key={a.host_id}>
                          <td
                            className="mono"
                            style={{
                              fontWeight: 700,
                              color: "var(--accent-cyan)",
                            }}
                          >
                            {a.host_id}
                          </td>
                          <td className="mono">{a.asset_type}</td>
                          <td>
                            <span className="soc-pill neutral">{a.category}</span>
                          </td>
                          <td>{a.os}</td>
                          <td>
                            <StatusPill
                              level={a.criticality}
                              label={a.criticality}
                            />
                          </td>
                          <td>
                            <StatusPill level={a.status} label={a.status} />
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}

          {/* ==============================================================
              PAGE 7: LIVE AGENT OPERATIONS (#/agents)
             ============================================================== */}
          {route.page === "agents" && (
            <MasterCyberConsole runId={runId} embedded={true} />
          )}
        </main>
      </div>

      {pdfModalReport && (
        <PdfViewerModal
          report={pdfModalReport}
          runId={runId}
          onClose={() => setPdfModalReport(null)}
        />
      )}

      {toolboxOpen && (
        <SimulationToolboxModal
          runId={runId}
          onClose={() => setToolboxOpen(false)}
          onSuccess={() => loadRunAll(runId)}
        />
      )}
    </div>
  );
}
