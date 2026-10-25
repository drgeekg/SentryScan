import React, { useState, useEffect, useMemo } from "react";

const AGENT_NODES = [
  { id: "fleet_sensor", label: "Fleet Sensor", role: "Telemetry Ingest", x: 95, y: 80, tier: "sensor" },
  { id: "integrity_checker", label: "Integrity Checker", role: "FIM / Config Drift", x: 95, y: 195, tier: "sensor" },
  { id: "scanner_worker", label: "Scanner Worker", role: "Active Probe", x: 95, y: 310, tier: "sensor" },
  { id: "scout-agent", label: "Scout Agent", role: "Anomaly Detection", x: 280, y: 120, tier: "core" },
  { id: "triage-agent", label: "Triage Agent", role: "Severity & Context", x: 280, y: 265, tier: "core" },
  { id: "supervisor-agent", label: "Supervisor Agent", role: "Contract-Net Coordinator", x: 485, y: 195, tier: "supervisor" },
  { id: "worker-batch-alpha", label: "Worker Alpha", role: "Deep Inspection", x: 690, y: 95, tier: "worker" },
  { id: "worker-batch-beta", label: "Worker Beta", role: "Correlation Worker", x: 690, y: 295, tier: "worker" },
  { id: "analyst-l1-triage", label: "L1 Triage Analyst", role: "Alert Enrichment", x: 900, y: 80, tier: "soc" },
  { id: "analyst-l2-incident", label: "L2 Incident Lead", role: "Case Investigation", x: 900, y: 195, tier: "soc" },
  { id: "analyst-l3-containment", label: "L3 Containment", role: "Response & Quarantine Gate", x: 900, y: 310, tier: "soc" },
];

const DEFAULT_EDGES = [
  ["fleet_sensor", "scout-agent"],
  ["integrity_checker", "scout-agent"],
  ["scanner_worker", "triage-agent"],
  ["scout-agent", "supervisor-agent"],
  ["triage-agent", "supervisor-agent"],
  ["supervisor-agent", "worker-batch-alpha"],
  ["supervisor-agent", "worker-batch-beta"],
  ["supervisor-agent", "analyst-l1-triage"],
  ["analyst-l1-triage", "analyst-l2-incident"],
  ["analyst-l2-incident", "analyst-l3-containment"],
];

export default function AgentOps({ runId, snapshot, liveEvents, onNavigate }) {
  const [selectedAgent, setSelectedAgent] = useState("supervisor-agent");
  const [cursor, setCursor] = useState(100);
  const [playing, setPlaying] = useState(false);
  const [speed, setSpeed] = useState(1);
  const [liveFollow, setLiveFollow] = useState(true);
  const [perfFilter, setPerfFilter] = useState("ALL");

  const allMessages = useMemo(() => {
    const snapMsgs = snapshot?.messages || [];
    return snapMsgs;
  }, [snapshot]);

  const allDelibs = useMemo(() => snapshot?.deliberations || [], [snapshot]);
  const allFindings = useMemo(() => snapshot?.findings || [], [snapshot]);
  const allIncidents = useMemo(() => snapshot?.incidents || [], [snapshot]);
  const allQuarantines = useMemo(() => snapshot?.quarantine_proposals || [], [snapshot]);

  const totalSteps = Math.max(allMessages.length, 1);

  useEffect(() => {
    if (liveFollow) {
      setCursor(totalSteps);
    }
  }, [totalSteps, liveFollow]);

  useEffect(() => {
    if (!playing) return;
    const ms = Math.max(80, Math.round(600 / speed));
    const timer = setInterval(() => {
      setCursor((prev) => {
        if (prev >= totalSteps) {
          setPlaying(false);
          return totalSteps;
        }
        return prev + 1;
      });
    }, ms);
    return () => clearInterval(timer);
  }, [playing, speed, totalSteps]);

  const visibleMessages = useMemo(() => {
    const sliced = allMessages.slice(0, cursor);
    if (perfFilter === "ALL") return sliced;
    return sliced.filter((m) => (m.performative || "").toUpperCase() === perfFilter);
  }, [allMessages, cursor, perfFilter]);

  const recentEdges = useMemo(() => {
    const windowMsgs = allMessages.slice(Math.max(0, cursor - 6), cursor);
    return windowMsgs.map((m) => ({
      from: m.sender,
      to: m.recipient,
      performative: m.performative,
    }));
  }, [allMessages, cursor]);

  const agentStats = useMemo(() => {
    const stats = {};
    AGENT_NODES.forEach((n) => {
      stats[n.id] = { sent: 0, received: 0, lastPerf: "IDLE", deliberations: [] };
    });
    allMessages.slice(0, cursor).forEach((m) => {
      if (stats[m.sender]) {
        stats[m.sender].sent += 1;
        stats[m.sender].lastPerf = m.performative || "MSG";
      }
      if (stats[m.recipient]) {
        stats[m.recipient].received += 1;
      }
    });
    allDelibs.forEach((d) => {
      const aid = d.agent_id || "supervisor-agent";
      if (!stats[aid]) stats[aid] = { sent: 0, received: 0, lastPerf: "ACTIVE", deliberations: [] };
      stats[aid].deliberations.push(d);
    });
    return stats;
  }, [allMessages, allDelibs, cursor]);

  const nodeMap = useMemo(() => {
    const m = {};
    AGENT_NODES.forEach((n) => {
      m[n.id] = n;
    });
    return m;
  }, []);

  const currentAgentInfo = nodeMap[selectedAgent] || AGENT_NODES[5];
  const currentAgentStat = agentStats[selectedAgent] || { sent: 0, received: 0, lastPerf: "IDLE", deliberations: [] };

  const agentMessages = useMemo(() => {
    return visibleMessages
      .filter((m) => m.sender === selectedAgent || m.recipient === selectedAgent)
      .slice(-25)
      .reverse();
  }, [visibleMessages, selectedAgent]);

  return (
    <div>
      {/* Replay Scrubber Controls */}
      <div className="panel" style={{ marginBottom: 16 }}>
        <div className="panel-body" style={{ display: "flex", alignItems: "center", gap: 14, flexWrap: "wrap" }}>
          <button
            className="btn btn-primary btn-sm"
            onClick={() => {
              setLiveFollow(false);
              if (cursor >= totalSteps) setCursor(1);
              setPlaying(!playing);
            }}
          >
            {playing ? "Pause Replay" : "Play Replay"}
          </button>
          <button
            className="btn btn-sm"
            onClick={() => {
              setPlaying(false);
              setLiveFollow(false);
              setCursor(1);
            }}
          >
            Restart
          </button>
          <div style={{ display: "flex", alignItems: "center", gap: 8, flex: 1, minWidth: 220 }}>
            <span style={{ fontSize: 12, color: "var(--text-secondary)", fontFamily: "var(--font-mono)" }}>
              Step {cursor} / {totalSteps}
            </span>
            <input
              type="range"
              min={1}
              max={totalSteps}
              value={cursor}
              onChange={(e) => {
                setLiveFollow(false);
                setCursor(Number(e.target.value));
              }}
              style={{ flex: 1 }}
              aria-label="Investigation timeline scrubber"
            />
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
            <span style={{ fontSize: 12, color: "var(--text-secondary)" }}>Speed:</span>
            {[0.5, 1, 2, 4].map((s) => (
              <button
                key={s}
                className={`btn btn-sm ${speed === s ? "btn-primary" : ""}`}
                onClick={() => setSpeed(s)}
              >
                {s}x
              </button>
            ))}
          </div>
          <label style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 12, cursor: "pointer" }}>
            <input
              type="checkbox"
              checked={liveFollow}
              onChange={(e) => setLiveFollow(e.target.checked)}
            />
            Live Follow
          </label>
        </div>
      </div>

      {/* Interactive SVG Agent Topology & Selected Agent Inspector */}
      <div className="grid-sidebar" style={{ marginBottom: 16 }}>
        <div className="panel">
          <div className="panel-header">
            <div>
              <div className="panel-title">Multi-Agent Contract-Net &amp; BDI Workflow Graph</div>
              <div className="panel-subtitle">
                Click any agent node to inspect its messages, BDI beliefs/intentions, and tool calls
              </div>
            </div>
            <span className="status-pill info">11 AGENTS REGISTERED</span>
          </div>
          <div className="panel-body" style={{ padding: 12 }}>
            <svg className="agent-graph-svg" viewBox="0 0 1020 385" role="img" aria-label="Agent topology graph">
              <defs>
                <marker id="arrow-idle" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
                  <path d="M 0 1 L 10 5 L 0 9 z" fill="var(--border-strong)" />
                </marker>
                <marker id="arrow-active" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
                  <path d="M 0 1 L 10 5 L 0 9 z" fill="var(--brand-primary)" />
                </marker>
              </defs>

              {/* Tier Column Labels */}
              <text x="95" y="26" textAnchor="middle" fill="var(--text-muted)" fontSize="11" fontWeight="700">
                SENSORS
              </text>
              <text x="280" y="26" textAnchor="middle" fill="var(--text-muted)" fontSize="11" fontWeight="700">
                DETECTION &amp; TRIAGE
              </text>
              <text x="485" y="26" textAnchor="middle" fill="var(--text-muted)" fontSize="11" fontWeight="700">
                BDI SUPERVISOR
              </text>
              <text x="690" y="26" textAnchor="middle" fill="var(--text-muted)" fontSize="11" fontWeight="700">
                CONTRACT WORKERS
              </text>
              <text x="900" y="26" textAnchor="middle" fill="var(--text-muted)" fontSize="11" fontWeight="700">
                SOC ANALYST TIERS
              </text>

              {/* Base Structural Edges */}
              {DEFAULT_EDGES.map(([fromId, toId], idx) => {
                const a = nodeMap[fromId];
                const b = nodeMap[toId];
                if (!a || !b) return null;
                const isActive = recentEdges.some(
                  (e) => (e.from === fromId && e.to === toId) || (e.from === toId && e.to === fromId)
                );
                return (
                  <line
                    key={idx}
                    x1={a.x}
                    y1={a.y}
                    x2={b.x}
                    y2={b.y}
                    stroke={isActive ? "var(--brand-primary)" : "var(--border-strong)"}
                    strokeWidth={isActive ? 2.5 : 1.4}
                    strokeDasharray={isActive ? "none" : "4 4"}
                    markerEnd={isActive ? "url(#arrow-active)" : "url(#arrow-idle)"}
                  />
                );
              })}

              {/* Agent Nodes */}
              {AGENT_NODES.map((node) => {
                const st = agentStats[node.id] || { sent: 0, received: 0, lastPerf: "IDLE" };
                const isSelected = selectedAgent === node.id;
                const isActive = st.sent + st.received > 0;
                return (
                  <g
                    key={node.id}
                    transform={`translate(${node.x - 72}, ${node.y - 30})`}
                    onClick={() => setSelectedAgent(node.id)}
                    style={{ cursor: "pointer" }}
                  >
                    <rect
                      width="144"
                      height="62"
                      rx="8"
                      fill={isSelected ? "var(--bg-selected)" : "var(--bg-surface)"}
                      stroke={isSelected ? "var(--brand-primary)" : isActive ? "var(--sev-info)" : "var(--border-strong)"}
                      strokeWidth={isSelected ? "2.4" : "1.4"}
                    />
                    <circle
                      cx="14"
                      cy="16"
                      r="4.5"
                      fill={isActive ? "var(--sev-low)" : "var(--text-muted)"}
                    />
                    <text x="24" y="19" fill="var(--text-primary)" fontSize="11.5" fontWeight="700">
                      {node.label}
                    </text>
                    <text x="12" y="35" fill="var(--text-secondary)" fontSize="10.5">
                      {node.role}
                    </text>
                    <text x="12" y="51" fill="var(--text-muted)" fontSize="10" fontFamily="var(--font-mono)">
                      tx:{st.sent} rx:{st.received} [{st.lastPerf}]
                    </text>
                  </g>
                );
              })}
            </svg>
          </div>
        </div>

        {/* Selected Agent Inspector */}
        <div className="panel">
          <div className="panel-header">
            <div>
              <div className="panel-title">{currentAgentInfo.label}</div>
              <div className="panel-subtitle">
                <span className="mono">{currentAgentInfo.id}</span> · {currentAgentInfo.role}
              </div>
            </div>
            <span className={`status-pill ${currentAgentStat.sent + currentAgentStat.received > 0 ? "pass" : "neutral"}`}>
              {currentAgentStat.lastPerf}
            </span>
          </div>
          <div className="panel-body">
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10, marginBottom: 14 }}>
              <div style={{ padding: 10, background: "var(--bg-elevated)", borderRadius: 6, border: "1px solid var(--border-subtle)" }}>
                <div style={{ fontSize: 11, color: "var(--text-secondary)" }}>MESSAGES SENT</div>
                <div style={{ fontSize: 20, fontWeight: 700, fontFamily: "var(--font-mono)" }}>{currentAgentStat.sent}</div>
              </div>
              <div style={{ padding: 10, background: "var(--bg-elevated)", borderRadius: 6, border: "1px solid var(--border-subtle)" }}>
                <div style={{ fontSize: 11, color: "var(--text-secondary)" }}>MESSAGES RECEIVED</div>
                <div style={{ fontSize: 20, fontWeight: 700, fontFamily: "var(--font-mono)" }}>{currentAgentStat.received}</div>
              </div>
            </div>

            <div style={{ fontSize: 12, fontWeight: 700, marginBottom: 8 }}>Recent Agent Messages</div>
            {agentMessages.length === 0 ? (
              <div className="empty-state" style={{ padding: 16 }}>
                No messages recorded for this agent at current step.
              </div>
            ) : (
              <div style={{ maxHeight: 230, overflowY: "auto" }} className="timeline-list">
                {agentMessages.slice(0, 8).map((m, i) => (
                  <div key={i} className="timeline-item" style={{ padding: 8 }}>
                    <div className="timeline-meta">
                      <span className="status-pill info">{m.performative}</span>
                      <span className="mono">
                        {m.sender} → {m.recipient}
                      </span>
                    </div>
                    <div style={{ fontSize: 12, color: "var(--text-secondary)", fontFamily: "var(--font-mono)" }}>
                      {JSON.stringify(m.content || {}).slice(0, 140)}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Bottom Split: Contract-Net Message Bus + BDI Deliberations & Approval Gates */}
      <div className="grid-2">
        <div className="panel">
          <div className="panel-header">
            <div>
              <div className="panel-title">Contract-Net Protocol Message Bus</div>
              <div className="panel-subtitle">Task announcements (CFP), bids (PROPOSE), awards (ACCEPT), and alerts</div>
            </div>
            <select
              className="select-input"
              value={perfFilter}
              onChange={(e) => setPerfFilter(e.target.value)}
              aria-label="Filter by performative"
            >
              <option value="ALL">All Performatives ({allMessages.slice(0, cursor).length})</option>
              <option value="CFP">CFP (Call For Proposals)</option>
              <option value="PROPOSE">PROPOSE (Worker Bids)</option>
              <option value="ACCEPT">ACCEPT (Awarded Tasks)</option>
              <option value="ALERT">ALERT (Escalations)</option>
              <option value="INFORM">INFORM (Results)</option>
            </select>
          </div>
          <div className="data-table-wrap" style={{ maxHeight: 320, overflowY: "auto" }}>
            <table className="data-table">
              <thead>
                <tr>
                  <th>Performative</th>
                  <th>Sender</th>
                  <th>Recipient</th>
                  <th>Correlation / Summary</th>
                </tr>
              </thead>
              <tbody>
                {visibleMessages.length === 0 ? (
                  <tr>
                    <td colSpan={4} className="empty-state">
                      No messages match filter in current replay window.
                    </td>
                  </tr>
                ) : (
                  visibleMessages
                    .slice(-40)
                    .reverse()
                    .map((m, idx) => (
                      <tr key={idx}>
                        <td>
                          <span className="status-pill info">{m.performative}</span>
                        </td>
                        <td className="mono">{m.sender}</td>
                        <td className="mono">{m.recipient}</td>
                        <td className="mono" style={{ fontSize: 12, color: "var(--text-secondary)" }}>
                          {m.correlation_id ? `[${m.correlation_id}] ` : ""}
                          {JSON.stringify(m.content || {}).slice(0, 95)}
                        </td>
                      </tr>
                    ))
                )}
              </tbody>
            </table>
          </div>
        </div>

        <div className="panel">
          <div className="panel-header">
            <div>
              <div className="panel-title">BDI Deliberation &amp; Approval Gates</div>
              <div className="panel-subtitle">Supervisor belief updates, active intentions, and L3 containment gates</div>
            </div>
            <span className="status-pill medium">{allDelibs.length} CYCLES</span>
          </div>
          <div className="panel-body" style={{ maxHeight: 320, overflowY: "auto" }}>
            {allQuarantines.length > 0 && (
              <div style={{ marginBottom: 14 }}>
                <div style={{ fontSize: 12, fontWeight: 700, marginBottom: 6 }}>L3 Containment Approval Gates</div>
                {allQuarantines.map((q) => (
                  <div
                    key={q.proposal_id}
                    style={{
                      padding: 10,
                      borderRadius: 6,
                      border: "1px solid var(--border-subtle)",
                      background: "var(--bg-elevated)",
                      marginBottom: 8,
                      display: "flex",
                      justifyContent: "space-between",
                      alignItems: "center",
                    }}
                  >
                    <div>
                      <div style={{ fontWeight: 600, fontSize: 13 }}>
                        Isolate <span className="mono">{q.host_id}</span> ({q.action})
                      </div>
                      <div style={{ fontSize: 12, color: "var(--text-secondary)" }}>
                        Incident: <span className="mono">{q.incident_id}</span> · Proposed by {q.proposed_by}
                      </div>
                    </div>
                    <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
                      <span
                        className={`status-pill ${
                          q.status === "approved" ? "pass" : q.status === "rejected" ? "critical" : "high"
                        }`}
                      >
                        {q.status.toUpperCase()}
                      </span>
                      {onNavigate && (
                        <button
                          className="btn btn-sm"
                          onClick={() => onNavigate(`#/proact/incident/${q.incident_id}`)}
                        >
                          Inspect Case
                        </button>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            )}

            <div style={{ fontSize: 12, fontWeight: 700, marginBottom: 6 }}>Supervisor BDI Trace</div>
            {allDelibs.length === 0 ? (
              <div className="empty-state" style={{ padding: 16 }}>
                No BDI deliberation snapshots recorded for this run yet.
              </div>
            ) : (
              <div className="timeline-list">
                {allDelibs.slice(-10).reverse().map((d, idx) => (
                  <div key={idx} className="timeline-item">
                    <div className="timeline-meta">
                      <span className="status-pill pass">BDI CYCLE #{d.cycle ?? idx + 1}</span>
                      <span className="mono">{d.agent_id || "supervisor-agent"}</span>
                      <span>{d.timestamp ? new Date(d.timestamp).toLocaleTimeString() : ""}</span>
                    </div>
                    <div style={{ fontSize: 12, color: "var(--text-secondary)", fontFamily: "var(--font-mono)" }}>
                      Selected: {JSON.stringify(d.selected_intention || d.intentions || d.desires || {}).slice(0, 140)}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
