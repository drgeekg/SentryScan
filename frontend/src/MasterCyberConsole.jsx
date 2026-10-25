import React, { useState, useEffect, useMemo, useCallback, useRef } from "react";
import PdfViewerModal from "./PdfViewerModal.jsx";

const POS = {
  fleet_sensor: [70, 260],
  integrity_checker: [195, 420],
  scanner_worker: [225, 260],
  "supervisor-agent": [460, 260],
  "scout-agent": [430, 75],
  "triage-agent": [430, 445],
  "worker-batch-alpha": [680, 115],
  "worker-batch-beta": [680, 405],
  "analyst-l1-triage": [905, 105],
  "analyst-l2-incident": [905, 260],
  "analyst-l3-containment": [905, 415],
};

const ROLE = {
  integrity_checker: "Screens telemetry for replay, staleness and contradictions; rejects poisoned records",
  fleet_sensor: "Streams synthetic telemetry from the 11-class enterprise device fleet",
  scanner_worker: "Plain-Python rule engine; matches telemetry to vulnerability & protocol rules",
  "supervisor-agent": "Runs Contract-Net negotiation, fans out workers, dispatches findings to SOC L1",
  "scout-agent": "Bids for broad host coverage within budget constraints",
  "triage-agent": "Bids for high-severity, high-confidence findings first",
  "worker-batch-alpha": "Evaluates assigned alpha batch of screened telemetry records",
  "worker-batch-beta": "Evaluates assigned beta batch of screened telemetry records",
  "analyst-l1-triage": "SOC Tier 1 (Triage): Screens all findings, enriches CVEs, escalates HIGH/CRITICAL to L2",
  "analyst-l2-incident": "SOC Tier 2 (Incident): Correlates escalated alerts, tightens scan cadence, escalates CRITICAL to L3",
  "analyst-l3-containment": "SOC Tier 3 (Containment): Exclusive authority to isolate/quarantine compromised hosts",
};

const PCOL = {
  CFP: "#4da3ff",
  PROPOSE: "#f5d547",
  COUNTERPROPOSE: "#ff9a3c",
  ACCEPT: "#5dff9d",
  CONFIRM: "#5dff9d",
  REJECT: "#ff4d5e",
  TASK_REQUEST: "#4de0e0",
  TASK_RESULT: "#4de0e0",
  PARAMS_UPDATE: "#b18cff",
  STATE_SYNC: "#b18cff",
  ALERT: "#ff4d5e",
  ERROR: "#ff4d5e",
};

const NEG_SET = new Set(["CFP", "PROPOSE", "COUNTERPROPOSE", "ACCEPT", "REJECT", "CONFIRM"]);

const TABS = [
  ["agent", "Inspector"],
  ["tools", "⚡ Toolbox"],
  ["copilot", "Copilot Q&A"],
  ["reports", "Reports"],
  ["incidents", "Incidents"],
  ["neg", "Negotiation"],
  ["fleet", "Fleet"],
  ["find", "Findings"],
  ["log", "Log"],
];

const COPILOT_CHIPS = [
  "Which hosts are quarantined?",
  "List critical CVEs",
  "Summarize fleet posture",
  "Explain agent negotiation",
  "Show failing POLARIS controls",
  "List high-risk SENTRA exposures",
];

const REPORT_WINDOWS = [
  "Last 15 Minutes",
  "Last 30 Minutes",
  "Last 1 Hour",
  "Full Run (All Batches)",
];

const norm = (c) => (c === "supervisor" ? "supervisor-agent" : c || "");

export default function MasterCyberConsole({ runId, onBack, embedded = false }) {
  const [runs, setRuns] = useState([]);
  const [activeRunId, setActiveRunId] = useState(runId || "run-live");
  const [runMode, setRunMode] = useState("LIVE");
  const [wsLink, setWsLink] = useState("connecting");

  const [events, setEvents] = useState([]);
  const [messages, setMessages] = useState([]);
  const [findings, setFindings] = useState([]);
  const [devices, setDevices] = useState([]);
  const [bdi, setBdi] = useState([]);
  const [reports, setReports] = useState([]);
  const [incidents, setIncidents] = useState([]);
  const [quarantines, setQuarantines] = useState([]);

  // Playback & Scrubber
  const [pos, setPos] = useState(0);
  const [playing, setPlaying] = useState(true);
  const [followLive, setFollowLive] = useState(true);
  const [speed, setSpeed] = useState(1);

  // Selection & Tabs
  const [activeTab, setActiveTab] = useState("agent");
  const [selectedAgent, setSelectedAgent] = useState("supervisor-agent");
  const [selectedEventIdx, setSelectedEventIdx] = useState(null);

  // Copilot
  const [chatHistory, setChatHistory] = useState([
    {
      role: "copilot",
      text: "SentryScan Autonomous Threat Copilot online. Click any pre-prompt chip above or ask about active alerts, quarantined hosts, telemetry, or Contract-Net negotiation.",
      time: new Date().toLocaleTimeString(),
    },
  ]);
  const [chatInput, setChatInput] = useState("");
  const [chatLoading, setChatLoading] = useState(false);

  // Reports
  const [reportWindow, setReportWindow] = useState("Last 30 Minutes");
  const [generatingReport, setGeneratingReport] = useState(false);
  const [expandedReportIdx, setExpandedReportIdx] = useState(0);
  const [pdfModalReport, setPdfModalReport] = useState(null);
  const [reportFilter, setReportFilter] = useState("all");

  // Simulation & Threat Injection Toolbox State
  const [toolInjecting, setToolInjecting] = useState(false);
  const [toolStatus, setToolStatus] = useState(null);
  const [toolTargetHost, setToolTargetHost] = useState("");
  const [toolPreset, setToolPreset] = useState("apache_cve");
  const [toolRecordCount, setToolRecordCount] = useState(5);
  const [toolPoisonRate, setToolPoisonRate] = useState(0.0);
  const [toolCustomService, setToolCustomService] = useState("http");
  const [toolCustomPort, setToolCustomPort] = useState(80);
  const [toolCustomBanner, setToolCustomBanner] = useState("Apache/2.4.49 (Unix)");
  const [toolQuarImmediate, setToolQuarImmediate] = useState(false);
  const [toolSimPace, setToolSimPace] = useState(0.5);
  const [toolSimPoison, setToolSimPoison] = useState(0.2);
  const [toolSimProfile, setToolSimProfile] = useState("enterprise");
  const [toolQuarTarget, setToolQuarTarget] = useState("");

  const lanesScrollRef = useRef(null);

  useEffect(() => {
    if (runId) setActiveRunId(runId);
  }, [runId]);

  useEffect(() => {
    fetch("/api/runs")
      .then((r) => (r.ok ? r.json() : []))
      .then((data) => {
        const list = Array.isArray(data) ? data : data.runs || [];
        setRuns(list);
        if (list.length > 0 && !activeRunId) {
          setActiveRunId(list[0].run_id || list[0]);
        }
      })
      .catch(() => {});
  }, [activeRunId]);

  const refreshSideData = useCallback(async (rid) => {
    if (!rid) return;
    try {
      const [fRes, dRes, bRes, rRes, aRes, qRes] = await Promise.all([
        fetch(`/api/runs/${rid}/findings`).then((r) => (r.ok ? r.json() : null)),
        fetch(`/api/runs/${rid}/devices`).then((r) => (r.ok ? r.json() : null)),
        fetch(`/api/runs/${rid}/bdi`).then((r) => (r.ok ? r.json() : null)),
        fetch(`/api/runs/${rid}/reports`).then((r) => (r.ok ? r.json() : null)),
        fetch(`/api/runs/${rid}/analysis`).then((r) => (r.ok ? r.json() : null)),
        fetch(`/api/runs/${rid}/quarantines`).then((r) => (r.ok ? r.json() : null)),
      ]);
      if (fRes) setFindings(Array.isArray(fRes) ? fRes : fRes.findings || []);
      if (dRes) setDevices(Array.isArray(dRes) ? dRes : dRes.devices || []);
      if (bRes) setBdi(Array.isArray(bRes) ? bRes : bRes.snapshots || []);
      if (rRes) setReports(Array.isArray(rRes) ? rRes : rRes.reports || []);
      if (aRes) setIncidents(Array.isArray(aRes) ? aRes : aRes.incidents || []);
      if (qRes) setQuarantines(Array.isArray(qRes) ? qRes : qRes.quarantines || []);
    } catch (_e) {}
  }, []);

  const loadFullRun = useCallback(
    async (rid) => {
      if (!rid) return;
      try {
        const [runMeta, evRes, msgRes] = await Promise.all([
          fetch(`/api/runs/${rid}`).then((r) => (r.ok ? r.json() : null)),
          fetch(`/api/runs/${rid}/events?limit=2500`).then((r) => (r.ok ? r.json() : null)),
          fetch(`/api/runs/${rid}/messages`).then((r) => (r.ok ? r.json() : null)),
        ]);
        const evList = Array.isArray(evRes) ? evRes : evRes?.events || [];
        const msgList = Array.isArray(msgRes) ? msgRes : msgRes?.messages || [];
        setEvents(evList);
        setMessages(msgList);
        setPos(evList.length);
        setFollowLive(true);
        const isLiveRun = rid === "run-live" || runMeta?.status === "RUNNING";
        setRunMode(isLiveRun ? "LIVE" : "REPLAY");
        await refreshSideData(rid);
      } catch (_e) {}
    },
    [refreshSideData]
  );

  useEffect(() => {
    loadFullRun(activeRunId);
  }, [activeRunId, loadFullRun]);

  // WebSocket with mandatory {type: "subscribe", from_seq} handshake!
  useEffect(() => {
    if (!activeRunId) return;
    const proto = window.location.protocol === "https:" ? "wss:" : "ws:";
    const wsUrl = `${proto}//${window.location.host}/ws/${activeRunId}`;
    let ws;
    let pollTimer;

    try {
      ws = new WebSocket(wsUrl);
      ws.onopen = () => {
        setWsLink("live");
        ws.send(JSON.stringify({ type: "subscribe", from_seq: 1 }));
      };
      ws.onclose = () => setWsLink("closed");
      ws.onerror = () => setWsLink("error");
      ws.onmessage = (evt) => {
        try {
          const msg = JSON.parse(evt.data);
          const e = (msg.type === "event" && msg.data) ? msg.data : (msg.seq && msg.event_type ? msg : null);
          if (e) {
            setEvents((prev) => {
              if (prev.length && e.seq <= prev[prev.length - 1].seq) return prev;
              const next = [...prev, e];
              if (followLive) {
                setPos(next.length);
              }
              return next;
            });
            if (e.event_type === "message_sent" && e.details) {
              setMessages((prev) => [
                ...prev,
                {
                  sender: norm(e.component),
                  receiver: norm(e.details.receiver),
                  performative: e.details.performative,
                  payload: e.details.payload || e.details,
                  timestamp_utc: e.timestamp_utc,
                },
              ]);
            }
            if (
              e.event_type === "finding_created" ||
              e.event_type === "state_transition" ||
              e.event_type === "report_written" ||
              e.event_type === "params_update"
            ) {
              refreshSideData(activeRunId);
            }
          }
        } catch (_e) {}
      };
    } catch (_e) {
      setWsLink("offline");
    }

    // Periodic refresh for live runs so side tabs stay 100% synced
    pollTimer = setInterval(() => {
      refreshSideData(activeRunId);
    }, 3500);

    return () => {
      if (ws) ws.close();
      if (pollTimer) clearInterval(pollTimer);
    };
  }, [activeRunId, followLive, refreshSideData]);

  // Playback tick when scrubbing/replaying
  useEffect(() => {
    if (!playing || followLive) return;
    const ms = Math.max(40, Math.round(250 / speed));
    const timer = setInterval(() => {
      setPos((prev) => {
        if (prev >= events.length) {
          setFollowLive(true);
          return events.length;
        }
        return prev + 1;
      });
    }, ms);
    return () => clearInterval(timer);
  }, [playing, followLive, speed, events.length]);

  // Derived prepared events & messages up to `pos`
  const derived = useMemo(() => {
    const n = Math.min(Math.max(0, pos), events.length);
    const slice = events.slice(0, n);
    const agentState = {};
    Object.keys(POS).forEach((id) => {
      agentState[id] = { in: 0, out: 0, rej: 0, find: 0, last: null };
    });

    const edgeCounts = {};
    const baseEdges = [
      ["fleet_sensor", "integrity_checker"],
      ["integrity_checker", "scanner_worker"],
      ["scanner_worker", "supervisor-agent"],
      ["supervisor-agent", "scout-agent"],
      ["supervisor-agent", "triage-agent"],
      ["supervisor-agent", "worker-batch-alpha"],
      ["supervisor-agent", "worker-batch-beta"],
      ["worker-batch-alpha", "analyst-l1-triage"],
      ["worker-batch-beta", "analyst-l1-triage"],
      ["analyst-l1-triage", "analyst-l2-incident"],
      ["analyst-l2-incident", "analyst-l3-containment"],
    ];
    baseEdges.forEach(([a, b]) => {
      edgeCounts[`${a}>${b}`] = 0;
    });

    const msgEvents = [];
    const quarantinedHosts = new Set();
    let rejCount = 0;

    slice.forEach((rawEv, idx) => {
      const ag = norm(rawEv.component);
      const to = norm(rawEv.details?.receiver || "");
      if (!agentState[ag] && POS[ag]) {
        agentState[ag] = { in: 0, out: 0, rej: 0, find: 0, last: null };
      }
      if (agentState[ag]) agentState[ag].last = rawEv;

      if (rawEv.event_type === "record_received") {
        if (agentState["fleet_sensor"]) agentState["fleet_sensor"].out++;
        if (agentState["integrity_checker"]) agentState["integrity_checker"].in++;
        edgeCounts["fleet_sensor>integrity_checker"] = (edgeCounts["fleet_sensor>integrity_checker"] || 0) + 1;
        if (!rawEv.details?.is_poisoned) {
          if (agentState["integrity_checker"]) agentState["integrity_checker"].out++;
          if (agentState["scanner_worker"]) {
            agentState["scanner_worker"].in++;
            agentState["scanner_worker"].out++;
          }
          edgeCounts["integrity_checker>scanner_worker"] = (edgeCounts["integrity_checker>scanner_worker"] || 0) + 1;
          edgeCounts["scanner_worker>supervisor-agent"] = (edgeCounts["scanner_worker>supervisor-agent"] || 0) + 1;
        }
      }

      if (rawEv.status === "REJECTED" || rawEv.event_type === "record_rejected") {
        rejCount++;
        if (agentState["integrity_checker"]) {
          agentState["integrity_checker"].rej++;
          agentState["integrity_checker"].out++;
        }
      }

      if (rawEv.event_type === "state_transition") {
        if (rawEv.component === "scanner_worker") {
          const cleanCount = rawEv.details?.clean_records || 1;
          if (agentState["integrity_checker"]) agentState["integrity_checker"].out += cleanCount;
          if (agentState["scanner_worker"]) {
            agentState["scanner_worker"].in += cleanCount;
            agentState["scanner_worker"].out += cleanCount;
          }
          edgeCounts["integrity_checker>scanner_worker"] = (edgeCounts["integrity_checker>scanner_worker"] || 0) + cleanCount;
          edgeCounts["scanner_worker>supervisor-agent"] = (edgeCounts["scanner_worker>supervisor-agent"] || 0) + 1;
        } else if (rawEv.component === "fleet_sensor") {
          const bSize = rawEv.details?.burst_size || rawEv.details?.size || rawEv.details?.count || 0;
          if (bSize > 0 && agentState["fleet_sensor"]) {
            agentState["fleet_sensor"].out += bSize;
          }
        }
        if (rawEv.details?.action === "quarantine_released") {
          quarantinedHosts.delete(rawEv.host_id);
        } else if (rawEv.details?.action === "quarantine_enforced" && rawEv.host_id) {
          quarantinedHosts.add(rawEv.host_id);
        }
      }

      if (rawEv.event_type === "finding_created") {
        if (agentState["scanner_worker"]) {
          agentState["scanner_worker"].find++;
          agentState["scanner_worker"].out++;
        }
        if (agentState["supervisor-agent"]) agentState["supervisor-agent"].in++;
        edgeCounts["scanner_worker>supervisor-agent"] = (edgeCounts["scanner_worker>supervisor-agent"] || 0) + 1;
        if (rawEv.details?.quarantined && rawEv.host_id) {
          quarantinedHosts.add(rawEv.host_id);
        }
      }

      if (rawEv.event_type === "message_sent") {
        const perf = rawEv.details?.performative || "INFORM";
        const payload = rawEv.details?.payload || rawEv.details || {};
        const msgObj = {
          sender: ag,
          receiver: to,
          performative: perf,
          payload,
          seq: rawEv.seq,
          evIndex: idx,
          timestamp_utc: rawEv.timestamp_utc,
        };
        msgEvents.push(msgObj);
        if (agentState[ag]) agentState[ag].out++;
        if (agentState[to]) agentState[to].in++;
        const k = `${ag}>${to}`;
        edgeCounts[k] = (edgeCounts[k] || 0) + 1;
        if (perf === "ALERT" && payload?.host_id) {
          quarantinedHosts.add(payload.host_id);
        }
      }
    });

    // Fallback to `/messages` endpoint if events stream didn't include message_sent rows
    if (msgEvents.length === 0 && messages.length > 0) {
      messages.forEach((m, idx) => {
        const ag = norm(m.sender);
        const to = norm(m.receiver);
        const perf = m.performative || "INFORM";
        msgEvents.push({
          sender: ag,
          receiver: to,
          performative: perf,
          payload: m.payload || {},
          seq: idx + 1,
          evIndex: idx,
          timestamp_utc: m.timestamp_utc,
        });
        if (agentState[ag]) agentState[ag].out++;
        if (agentState[to]) agentState[to].in++;
        const k = `${ag}>${to}`;
        edgeCounts[k] = (edgeCounts[k] || 0) + 1;
      });
    }

    findings.forEach((f) => {
      if (f.quarantined) quarantinedHosts.add(f.host_id);
    });

    const hotMsg = msgEvents.length > 0 ? msgEvents[msgEvents.length - 1] : null;
    const uniqueHosts = new Set(devices.map((d) => d.host_id)).size || 100;

    return {
      n,
      slice,
      agentState,
      edgeCounts,
      msgEvents,
      quarantinedHosts,
      rejCount,
      hotMsg,
      uniqueHosts,
    };
  }, [events, messages, findings, devices, pos]);

  // Actions
  const handleAskCopilot = async (questionOverride) => {
    const q = (questionOverride ?? chatInput).trim();
    if (!q || !activeRunId) return;
    setChatInput("");
    setChatHistory((prev) => [
      ...prev,
      { role: "user", text: q, time: new Date().toLocaleTimeString() },
    ]);
    setChatLoading(true);
    try {
      const res = await fetch(`/api/runs/${activeRunId}/ask`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ question: q }),
      });
      const data = await res.json();
      setChatHistory((prev) => [
        ...prev,
        {
          role: "copilot",
          text: data.answer || "No response generated.",
          latency: data.latency_ms,
          model: data.model || "sentryscan-copilot",
          time: new Date().toLocaleTimeString(),
        },
      ]);
    } catch (err) {
      setChatHistory((prev) => [
        ...prev,
        {
          role: "copilot",
          text: `Error reaching Copilot endpoint: ${err.message}`,
          time: new Date().toLocaleTimeString(),
        },
      ]);
    } finally {
      setChatLoading(false);
    }
  };

  const handleGenerateReport = async () => {
    if (!activeRunId || generatingReport) return;
    setGeneratingReport(true);
    try {
      const res = await fetch(`/api/runs/${activeRunId}/reports/generate`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ window_name: reportWindow }),
      });
      if (res.ok) {
        const rep = await res.json();
        setReports((prev) => [rep, ...prev]);
        setExpandedReportIdx(0);
      }
    } catch (_e) {}
    setGeneratingReport(false);
  };

  const handleQuarantineDecide = async (quarantineId, decision) => {
    if (!activeRunId) return;
    try {
      await fetch(`/api/runs/${activeRunId}/quarantines/${quarantineId}/decide`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ decision, decided_by: "console-operator" }),
      });
      await refreshSideData(activeRunId);
    } catch (_e) {}
  };

  const handleInjectTelemetry = async (overridePreset) => {
    if (!activeRunId || toolInjecting) return;
    setToolInjecting(true);
    setToolStatus(null);
    const chosenPreset = overridePreset || toolPreset;
    const body = {
      preset: chosenPreset,
      host_id: toolTargetHost || "windows-workstation-03",
      record_count: toolRecordCount,
      poison_rate: chosenPreset === "poison_storm" ? 1.0 : toolPoisonRate,
      quarantine_immediate: toolQuarImmediate,
      service: toolCustomService,
      port: toolCustomPort,
      banner: toolCustomBanner,
    };
    try {
      const res = await fetch(`/api/runs/${activeRunId}/telemetry/inject`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      const data = await res.json();
      if (res.ok) {
        setToolStatus({
          type: "success",
          msg: `Injected ${data.records_injected} records on ${data.host_id} (Clean: ${data.clean_verified}, Rej: ${data.poisoned_rejected}, Findings: ${data.findings_created})`,
        });
        await refreshSideData(activeRunId);
      } else {
        setToolStatus({ type: "error", msg: data.detail || "Injection failed" });
      }
    } catch (e) {
      setToolStatus({ type: "error", msg: e.message });
    } finally {
      setToolInjecting(false);
    }
  };

  const handleTuneSimulation = async () => {
    if (!activeRunId) return;
    try {
      const res = await fetch(`/api/runs/${activeRunId}/simulation/tune`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          pace: toolSimPace,
          poison_ratio: toolSimPoison,
          profile: toolSimProfile,
        }),
      });
      const data = await res.json();
      if (res.ok) {
        setToolStatus({
          type: "success",
          msg: `Simulation tuned: Pace ${toolSimPace}s · Poison ${Math.round(toolSimPoison * 100)}% · Profile: ${toolSimProfile}`,
        });
      }
    } catch (e) {
      setToolStatus({ type: "error", msg: e.message });
    }
  };

  const handleToggleQuarantine = async (hostId, action) => {
    if (!activeRunId || !hostId) return;
    try {
      const res = await fetch(`/api/runs/${activeRunId}/hosts/${hostId}/quarantine`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          action,
          reason: "Operator manual override from Simulation Toolbox",
        }),
      });
      const data = await res.json();
      if (res.ok) {
        setToolStatus({
          type: "success",
          msg: `Host ${hostId} ${action === "isolate" ? "QUARANTINED" : "RELEASED"} successfully.`,
        });
        await refreshSideData(activeRunId);
      }
    } catch (e) {
      setToolStatus({ type: "error", msg: e.message });
    }
  };

  const nodeIds = Object.keys(POS);
  const selectedEv = selectedEventIdx !== null ? events[selectedEventIdx] : null;
  const isContainment = derived.quarantinedHosts.size > 0;

  return (
    <div className={`mc-root ${isContainment ? "mc-alert" : ""} ${embedded ? "mc-embedded" : ""}`}>
      {/* TOP BAR */}
      <header className="mc-top">
        {onBack && (
          <button className="mc-back-btn" onClick={onBack}>
            ← Portal View
          </button>
        )}
        {!embedded && (
          <div className="mc-brand">
            <i />
            SentryScan
          </div>
        )}

        {!embedded && (
          <div className="mc-kv">
            <small>Run</small>
            <select
              className="mc-run-select"
              value={activeRunId}
              onChange={(e) => setActiveRunId(e.target.value)}
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
          </div>
        )}

        <div className="mc-kv">
          <small>Mode</small>
          <b>{runMode}</b>
        </div>

        <div className="mc-kv">
          <small>Link</small>
          <b>
            <span className={`mc-dot ${wsLink === "live" ? "live" : "err"}`} />
            {wsLink}
          </b>
        </div>

        <div className="mc-ctl" role="group" aria-label="Playback">
          <button
            onClick={() => {
              if (followLive) {
                setFollowLive(false);
                setPlaying(false);
              } else {
                setPlaying(!playing);
              }
            }}
            title="Play or Pause"
          >
            {playing && !followLive ? "❚❚" : "▶"}
          </button>
          <button
            onClick={() => {
              setFollowLive(false);
              setPlaying(true);
              setPos(1);
            }}
            title="Restart Replay"
          >
            ↻
          </button>
          <input
            type="range"
            min={0}
            max={Math.max(events.length, 1)}
            value={pos}
            onChange={(e) => {
              const v = Number(e.target.value);
              setPos(v);
              setFollowLive(v >= events.length);
            }}
          />
          <span className="mc-pos">
            {pos}/{events.length}
          </span>
          <select value={speed} onChange={(e) => setSpeed(Number(e.target.value))}>
            <option value={0.25}>0.25x</option>
            <option value={0.5}>0.5x</option>
            <option value={1}>1x</option>
            <option value={2}>2x</option>
            <option value={4}>4x</option>
            <option value={8}>8x</option>
          </select>
          <button
            className={followLive ? "on" : ""}
            onClick={() => {
              setFollowLive(true);
              setPos(events.length);
            }}
          >
            LIVE
          </button>
        </div>

        {!embedded && (
          <button
            className={`mc-tool-btn ${activeTab === "tools" ? "on" : ""}`}
            onClick={() => setActiveTab("tools")}
            title="Open Simulation & Telemetry Injection Toolbox"
          >
            ⚡ Threat Toolbox
          </button>
        )}

        <div className="mc-posture">
          <small>Posture</small>
          <h1>
            {isContainment
              ? "CONTAINMENT ACTIVE"
              : findings.length > 0
              ? "FINDINGS DETECTED"
              : "NOMINAL"}
          </h1>
        </div>

        <div className="mc-stats">
          <div>
            <small>Events</small>
            <b>{derived.n}</b>
          </div>
          <div>
            <small>Msgs</small>
            <b>{derived.msgEvents.length}</b>
          </div>
          <div>
            <small>Findings</small>
            <b className="c-high">{findings.length}</b>
          </div>
          <div>
            <small>Quarantined</small>
            <b className="c-crit">{derived.quarantinedHosts.size}</b>
          </div>
          <div>
            <small>Rejected</small>
            <b>{derived.rejCount}</b>
          </div>
          <div>
            <small>Devices</small>
            <b>{derived.uniqueHosts}</b>
          </div>
        </div>
      </header>

      {/* MAIN 2-COLUMN CONSOLE */}
      <div className="mc-main">
        {/* LEFT COLUMN: AGENT NETWORK SVG + CONVERSATION TIMELINE */}
        <div className="mc-left">
          <section className="mc-panel">
            <h2>
              Agent network <span className="mc-hint">click an agent to inspect BDI &amp; messages</span>
            </h2>
            <div className="mc-svgwrap">
              <svg viewBox="0 0 1000 520" preserveAspectRatio="xMidYMid meet">
                <defs>
                  <marker
                    id="mc-arr"
                    viewBox="0 0 10 10"
                    refX="9"
                    refY="5"
                    markerWidth="6"
                    markerHeight="6"
                    orient="auto-start-reverse"
                  >
                    <path d="M0,0 L10,5 L0,10 z" fill="#2c3f36" />
                  </marker>
                </defs>

                {/* EDGES */}
                {Object.entries(derived.edgeCounts).map(([key, count]) => {
                  const [a, b] = key.split(">");
                  const p1 = POS[a];
                  const p2 = POS[b];
                  if (!p1 || !p2) return null;
                  const mx = (p1[0] + p2[0]) / 2;
                  const my = (p1[1] + p2[1]) / 2 - 14;
                  const isHot =
                    derived.hotMsg &&
                    derived.hotMsg.sender === a &&
                    derived.hotMsg.receiver === b;
                  const hotColor = isHot
                    ? PCOL[derived.hotMsg.performative] || "#5dff9d"
                    : undefined;
                  return (
                    <g key={key}>
                      <path
                        d={`M${p1[0]},${p1[1]} Q${mx},${my} ${p2[0]},${p2[1]}`}
                        className={`mc-edge ${count > 0 ? "on" : ""} ${isHot ? "hot" : ""}`}
                        style={hotColor ? { stroke: hotColor } : undefined}
                        markerEnd="url(#mc-arr)"
                      />
                    </g>
                  );
                })}

                {/* HOT MESSAGE PILL LABEL */}
                {derived.hotMsg &&
                  POS[derived.hotMsg.sender] &&
                  POS[derived.hotMsg.receiver] && (
                    <text
                      x={
                        (POS[derived.hotMsg.sender][0] + POS[derived.hotMsg.receiver][0]) / 2
                      }
                      y={
                        (POS[derived.hotMsg.sender][1] + POS[derived.hotMsg.receiver][1]) / 2 -
                        18
                      }
                      textAnchor="middle"
                      fontSize="11"
                      fontWeight="700"
                      fill={PCOL[derived.hotMsg.performative] || "#5dff9d"}
                    >
                      {derived.hotMsg.performative}
                    </text>
                  )}

                {/* NODES */}
                {nodeIds.map((id) => {
                  const [x, y] = POS[id];
                  const st = derived.agentState[id] || { in: 0, out: 0 };
                  const isHot =
                    derived.hotMsg &&
                    (derived.hotMsg.sender === id || derived.hotMsg.receiver === id);
                  const isSel = selectedAgent === id;
                  const isAlert =
                    id.startsWith("analyst") && derived.quarantinedHosts.size > 0;
                  return (
                    <g
                      key={id}
                      className={`mc-node ${isHot ? "hot" : ""} ${isSel ? "sel" : ""} ${
                        isAlert ? "alert" : ""
                      }`}
                      transform={`translate(${x},${y})`}
                      onClick={() => {
                        setSelectedAgent(id);
                        setSelectedEventIdx(null);
                        setActiveTab("agent");
                      }}
                    >
                      <circle className="ring" r="34" />
                      <circle className="core" r="26" />
                      <text y="3" textAnchor="middle" fontSize="10" fontWeight="600" fill="#fff">
                        {id.replace("-agent", "").slice(0, 3).toUpperCase()}
                      </text>
                      <text y="46" textAnchor="middle" className="lbl">
                        {id}
                      </text>
                      <text y="-39" textAnchor="middle" className="cnt">
                        {id === "integrity_checker" && (st.rej > 0 || st.in > 0)
                          ? `in ${st.in} · rej ${st.rej}`
                          : id === "scanner_worker" && st.find > 0
                          ? `in ${st.in} · finds ${st.find}`
                          : `in ${st.in} · out ${st.out}`}
                      </text>
                    </g>
                  );
                })}
              </svg>
            </div>
            <div className="mc-legend">
              {Object.entries(PCOL).map(([k, c]) => (
                <span key={k}>
                  <i style={{ background: c }} />
                  {k}
                </span>
              ))}
            </div>
          </section>

          {/* CONVERSATION TIMELINE SWIMLANES */}
          <section className="mc-panel">
            <h2>
              Conversation timeline <span className="mc-hint">who talked to whom, in order</span>
            </h2>
            <div className="mc-scroll" ref={lanesScrollRef}>
              {(() => {
                const W = 980;
                const padL = 70;
                const padR = 30;
                const headH = 26;
                const rowH = 22;
                const cols = nodeIds;
                const xOf = (id) =>
                  padL +
                  (cols.indexOf(id) / Math.max(1, cols.length - 1)) * (W - padL - padR);
                const visibleMsgs = derived.msgEvents.slice(-120);
                const H = headH + Math.max(1, visibleMsgs.length) * rowH + 12;

                return (
                  <svg
                    viewBox={`0 0 ${W} ${H}`}
                    style={{ width: "100%", height: H, display: "block" }}
                  >
                    {cols.map((id) => {
                      const x = xOf(id);
                      return (
                        <g key={id}>
                          <line
                            x1={x}
                            y1={headH - 6}
                            x2={x}
                            y2={H}
                            stroke="#17211d"
                            strokeDasharray="2 4"
                          />
                          <text
                            x={x}
                            y="15"
                            textAnchor="middle"
                            fill="#6f857a"
                            fontSize="9.5"
                          >
                            {id.replace("-agent", "")}
                          </text>
                        </g>
                      );
                    })}

                    {visibleMsgs.map((m, i) => {
                      const y = headH + i * rowH + 10;
                      const x1 = xOf(m.sender);
                      const x2 = xOf(m.receiver);
                      const c = PCOL[m.performative] || "#5dff9d";
                      const dir = x2 >= x1 ? 1 : -1;
                      const isSel = selectedEventIdx === m.evIndex;
                      return (
                        <g
                          key={`${m.seq}-${i}`}
                          style={{ cursor: "pointer" }}
                          onClick={() => {
                            setSelectedEventIdx(m.evIndex);
                            setActiveTab("agent");
                          }}
                        >
                          {isSel && (
                            <rect
                              x="2"
                              y={y - 9}
                              width={W - 4}
                              height={rowH - 2}
                              fill="rgba(93,255,157,.09)"
                            />
                          )}
                          <text x="6" y={y + 3} fill="#6f857a" fontSize="9">
                            #{m.seq}
                          </text>
                          <line
                            x1={x1}
                            y1={y}
                            x2={x2 - dir * 6}
                            y2={y}
                            stroke={c}
                            strokeWidth="1.6"
                          />
                          <circle cx={x1} cy={y} r="2.8" fill={c} />
                          <polygon
                            points={`${x2},${y} ${x2 - dir * 6},${y - 3.5} ${
                              x2 - dir * 6
                            },${y + 3.5}`}
                            fill={c}
                          />
                          <text
                            x={(x1 + x2) / 2}
                            y={y - 3}
                            textAnchor="middle"
                            fill={c}
                            fontSize="9.5"
                          >
                            {m.performative}
                          </text>
                        </g>
                      );
                    })}
                  </svg>
                );
              })()}
            </div>
          </section>
        </div>

        {/* RIGHT SIDEBAR: 8 TABS */}
        <aside className="mc-panel mc-side">
          <div className="mc-tabs" role="tablist">
            {TABS.map(([key, label]) => (
              <button
                key={key}
                role="tab"
                className={activeTab === key ? "on" : ""}
                onClick={() => setActiveTab(key)}
              >
                {label}
              </button>
            ))}
          </div>

          <div className="mc-scroll mc-tabbody">
            {/* TAB 1: INSPECTOR */}
            {activeTab === "agent" && (
              <div>
                {selectedEv ? (
                  <div className="mc-card">
                    <div>
                      <span
                        className="mc-tag"
                        style={{
                          color:
                            PCOL[selectedEv.details?.performative] || "#5dff9d",
                        }}
                      >
                        {selectedEv.details?.performative || selectedEv.event_type}
                      </span>
                      <b>
                        #{selectedEv.seq} {norm(selectedEv.component)}
                        {selectedEv.details?.receiver
                          ? ` → ${norm(selectedEv.details.receiver)}`
                          : ""}
                      </b>
                    </div>
                    <div className="mc-muted" style={{ marginTop: 4 }}>
                      {selectedEv.timestamp_utc} · status {selectedEv.status || "OK"}
                    </div>
                    <pre className="mc-pre">
                      {JSON.stringify(
                        selectedEv.details?.payload || selectedEv.details || selectedEv,
                        null,
                        2
                      )}
                    </pre>
                  </div>
                ) : (
                  <>
                    <div className="mc-card">
                      <b>{selectedAgent}</b>
                      <div className="mc-muted" style={{ marginTop: 4 }}>
                        {ROLE[selectedAgent] || "Autonomous SOC Agent"}
                      </div>
                      <div style={{ marginTop: 6 }}>
                        sent <b>{derived.agentState[selectedAgent]?.out || 0}</b> · recv{" "}
                        <b>{derived.agentState[selectedAgent]?.in || 0}</b> · findings{" "}
                        <b>{derived.agentState[selectedAgent]?.find || 0}</b> · rejected{" "}
                        <b>{derived.agentState[selectedAgent]?.rej || 0}</b>
                      </div>
                    </div>

                    {selectedAgent.startsWith("analyst") && bdi.length > 0 && (
                      <div className="mc-card">
                        <small>BDI State (Belief-Desire-Intention)</small>
                        {(() => {
                          const snap =
                            bdi.filter((x) => x.agent_id === selectedAgent).slice(-1)[0] ||
                            bdi[bdi.length - 1];
                          return (
                            <>
                              <div style={{ marginTop: 4 }}>
                                desire <b>{snap.desire_type}</b> → intention{" "}
                                <b>{snap.intention_type}</b> on{" "}
                                <b>{snap.target_host || "none"}</b>
                              </div>
                              <pre className="mc-pre">
                                {JSON.stringify(snap.beliefs || snap, null, 2)}
                              </pre>
                            </>
                          );
                        })()}
                      </div>
                    )}

                    <small style={{ margin: "8px 0 4px" }}>
                      Recent messages involving {selectedAgent}
                    </small>
                    {derived.msgEvents
                      .filter(
                        (m) => m.sender === selectedAgent || m.receiver === selectedAgent
                      )
                      .slice(-30)
                      .reverse()
                      .map((m, idx) => (
                        <div
                          key={idx}
                          className="mc-row"
                          onClick={() => setSelectedEventIdx(m.evIndex)}
                        >
                          <span className="mc-muted">#{m.seq}</span>
                          <span>
                            <span
                              className="mc-tag"
                              style={{ color: PCOL[m.performative] || "#5dff9d" }}
                            >
                              {m.performative}
                            </span>
                            {m.sender} → {m.receiver}
                          </span>
                        </div>
                      ))}
                  </>
                )}
              </div>
            )}

            {/* TAB 2: SIMULATION & THREAT INJECTION TOOLBOX */}
            {activeTab === "tools" && (
              <div className="mc-toolbox">
                <div className="mc-card">
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                    <b>⚡ Simulation &amp; Threat Toolbox</b>
                    <span className="mc-tag" style={{ color: "#4da3ff" }}>LIVE OPERATOR INJECTOR</span>
                  </div>
                  <div className="mc-muted" style={{ marginTop: 4, fontSize: 11 }}>
                    Directly inject attacks, trigger CVE rule matches, test integrity screening, tune pace, or enforce quarantine.
                  </div>
                  {toolStatus && (
                    <div
                      style={{
                        marginTop: 8,
                        padding: "6px 10px",
                        borderRadius: 4,
                        fontSize: 11,
                        background: toolStatus.type === "success" ? "rgba(93,255,157,.12)" : "rgba(255,77,94,.12)",
                        color: toolStatus.type === "success" ? "#5dff9d" : "#ff4d5e",
                        border: `1px solid ${toolStatus.type === "success" ? "#5dff9d" : "#ff4d5e"}`,
                      }}
                    >
                      {toolStatus.msg}
                    </div>
                  )}
                </div>

                {/* SECTION 1: ONE-CLICK QUICK THREATS */}
                <div className="mc-card">
                  <small style={{ color: "#f5d547", fontWeight: 700, textTransform: "uppercase", letterSpacing: 0.5 }}>
                    1. One-Click Threat &amp; Telemetry Injections
                  </small>
                  <div style={{ display: "grid", gridTemplateColumns: "1fr", gap: 6, marginTop: 8 }}>
                    <button
                      className="mc-tool-action-btn crit"
                      disabled={toolInjecting}
                      onClick={() => handleInjectTelemetry("apache_cve")}
                    >
                      <span>🔴</span>
                      <div>
                        <b>Exploit: Apache 2.4.49 (CVE-2021-41773)</b>
                        <small>Matches RULE-005 (CRITICAL) → Escalates to L3 &amp; Auto-Quarantines</small>
                      </div>
                    </button>

                    <button
                      className="mc-tool-action-btn crit"
                      disabled={toolInjecting}
                      onClick={() => handleInjectTelemetry("default_creds")}
                    >
                      <span>🔴</span>
                      <div>
                        <b>Exploit: Default Admin Credentials (admin/admin)</b>
                        <small>Matches RULE-004 (CRITICAL) on Admin Portal Port 8080</small>
                      </div>
                    </button>

                    <button
                      className="mc-tool-action-btn high"
                      disabled={toolInjecting}
                      onClick={() => handleInjectTelemetry("telnet_leak")}
                    >
                      <span>🟡</span>
                      <div>
                        <b>Exposure: Cleartext Telnet Management</b>
                        <small>Matches RULE-001 (HIGH) on port 23 cleartext stream</small>
                      </div>
                    </button>

                    <button
                      className="mc-tool-action-btn poison"
                      disabled={toolInjecting}
                      onClick={() => handleInjectTelemetry("poison_storm")}
                    >
                      <span>🟠</span>
                      <div>
                        <b>Attack: Poisoned Telemetry Storm (100% Corrupted)</b>
                        <small>Tests Integrity Checker screening: contradictions, drift, replay</small>
                      </div>
                    </button>

                    <button
                      className="mc-tool-action-btn nominal"
                      disabled={toolInjecting}
                      onClick={() => handleInjectTelemetry("normal_traffic")}
                    >
                      <span>🟢</span>
                      <div>
                        <b>Traffic: Clean Benign Telemetry Burst (20 records)</b>
                        <small>Tests high-speed flow: Fleet Sensor → Integrity Checker → Scanner</small>
                      </div>
                    </button>
                  </div>
                </div>

                {/* SECTION 2: SIMULATION PARAMETER TUNER */}
                <div className="mc-card">
                  <small style={{ color: "#4da3ff", fontWeight: 700, textTransform: "uppercase", letterSpacing: 0.5 }}>
                    2. Simulation Pace &amp; Dynamics Tuner
                  </small>
                  <div style={{ marginTop: 8, display: "flex", flexDirection: "column", gap: 8 }}>
                    <div>
                      <div style={{ display: "flex", justifyContent: "space-between", fontSize: 11 }}>
                        <span className="mc-muted">Simulation Pace:</span>
                        <b>{toolSimPace}s / cycle {toolSimPace <= 0.2 ? "(Super Fast)" : toolSimPace >= 1.5 ? "(Slow & Steady)" : ""}</b>
                      </div>
                      <input
                        type="range"
                        min="0.1"
                        max="2.5"
                        step="0.1"
                        value={toolSimPace}
                        onChange={(e) => setToolSimPace(parseFloat(e.target.value))}
                        style={{ width: "100%", marginTop: 4 }}
                      />
                    </div>

                    <div>
                      <div style={{ display: "flex", justifyContent: "space-between", fontSize: 11 }}>
                        <span className="mc-muted">Background Poison Ratio:</span>
                        <b>{Math.round(toolSimPoison * 100)}%</b>
                      </div>
                      <input
                        type="range"
                        min="0.0"
                        max="0.8"
                        step="0.05"
                        value={toolSimPoison}
                        onChange={(e) => setToolSimPoison(parseFloat(e.target.value))}
                        style={{ width: "100%", marginTop: 4 }}
                      />
                    </div>

                    <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
                      <span className="mc-muted" style={{ fontSize: 11 }}>Profile:</span>
                      <select
                        className="mc-select"
                        value={toolSimProfile}
                        onChange={(e) => setToolSimProfile(e.target.value)}
                        style={{ flex: 1 }}
                      >
                        <option value="enterprise">Enterprise (Standard)</option>
                        <option value="soc_heavy">SOC Heavy (High Threat Volume)</option>
                        <option value="stealth">Stealth (Low &amp; Slow)</option>
                      </select>
                      <button
                        className="mc-btn-sm on"
                        onClick={handleTuneSimulation}
                        style={{ whiteSpace: "nowrap" }}
                      >
                        ⚙ Apply Tuner
                      </button>
                    </div>
                  </div>
                </div>

                {/* SECTION 3: MANUAL HOST QUARANTINE */}
                <div className="mc-card">
                  <small style={{ color: "#ff4d5e", fontWeight: 700, textTransform: "uppercase", letterSpacing: 0.5 }}>
                    3. Manual Asset Quarantine &amp; Isolation
                  </small>
                  <div style={{ marginTop: 8, display: "flex", flexDirection: "column", gap: 8 }}>
                    <div style={{ display: "flex", gap: 8 }}>
                      <select
                        className="mc-select"
                        value={toolQuarTarget}
                        onChange={(e) => setToolQuarTarget(e.target.value)}
                        style={{ flex: 1 }}
                      >
                        <option value="">-- Select Host Asset --</option>
                        {devices.map((d) => {
                          const isQ = derived.quarantinedHosts.has(d.host_id);
                          return (
                            <option key={d.host_id} value={d.host_id}>
                              {d.host_id} {isQ ? "[QUARANTINED]" : "[NOMINAL]"}
                            </option>
                          );
                        })}
                      </select>
                    </div>

                    <div style={{ display: "flex", gap: 8 }}>
                      <button
                        className="mc-btn-sm"
                        style={{ flex: 1, background: "rgba(255,77,94,.18)", color: "#ff4d5e", border: "1px solid #ff4d5e" }}
                        disabled={!toolQuarTarget}
                        onClick={() => handleToggleQuarantine(toolQuarTarget, "isolate")}
                      >
                        🛑 Isolate (Quarantine)
                      </button>
                      <button
                        className="mc-btn-sm"
                        style={{ flex: 1, background: "rgba(93,255,157,.18)", color: "#5dff9d", border: "1px solid #5dff9d" }}
                        disabled={!toolQuarTarget}
                        onClick={() => handleToggleQuarantine(toolQuarTarget, "release")}
                      >
                        🟢 Release Quarantine
                      </button>
                    </div>
                  </div>
                </div>

                {/* SECTION 4: CUSTOM TELEMETRY BATCH BUILDER */}
                <div className="mc-card">
                  <small style={{ color: "#5dff9d", fontWeight: 700, textTransform: "uppercase", letterSpacing: 0.5 }}>
                    4. Custom Telemetry Batch Builder
                  </small>
                  <div style={{ marginTop: 8, display: "flex", flexDirection: "column", gap: 8 }}>
                    <div style={{ display: "flex", gap: 8 }}>
                      <input
                        type="text"
                        className="mc-input"
                        placeholder="Target Host ID (or random)"
                        value={toolTargetHost}
                        onChange={(e) => setToolTargetHost(e.target.value)}
                        style={{ flex: 2 }}
                      />
                      <input
                        type="number"
                        className="mc-input"
                        placeholder="Port"
                        value={toolCustomPort}
                        onChange={(e) => setToolCustomPort(parseInt(e.target.value) || 80)}
                        style={{ flex: 1 }}
                      />
                    </div>

                    <div style={{ display: "flex", gap: 8 }}>
                      <input
                        type="text"
                        className="mc-input"
                        placeholder="Service name (http, ssh, ftp)"
                        value={toolCustomService}
                        onChange={(e) => setToolCustomService(e.target.value)}
                        style={{ flex: 1 }}
                      />
                      <input
                        type="text"
                        className="mc-input"
                        placeholder="Banner string..."
                        value={toolCustomBanner}
                        onChange={(e) => setToolCustomBanner(e.target.value)}
                        style={{ flex: 2 }}
                      />
                    </div>

                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                      <span className="mc-muted" style={{ fontSize: 11 }}>Batch Size: {toolRecordCount}</span>
                      <input
                        type="range"
                        min="1"
                        max="30"
                        value={toolRecordCount}
                        onChange={(e) => setToolRecordCount(parseInt(e.target.value))}
                        style={{ width: "60%" }}
                      />
                    </div>

                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                      <span className="mc-muted" style={{ fontSize: 11 }}>Poison: {Math.round(toolPoisonRate * 100)}%</span>
                      <input
                        type="range"
                        min="0"
                        max="1"
                        step="0.1"
                        value={toolPoisonRate}
                        onChange={(e) => setToolPoisonRate(parseFloat(e.target.value))}
                        style={{ width: "60%" }}
                      />
                    </div>

                    <button
                      className="mc-btn on"
                      disabled={toolInjecting}
                      onClick={() => handleInjectTelemetry("custom")}
                    >
                      {toolInjecting ? "Injecting Percepts..." : "🚀 Inject Telemetry Batch"}
                    </button>
                  </div>
                </div>
              </div>
            )}

            {/* TAB 3: COPILOT Q&A WITH PRE-PROMPTS */}
            {activeTab === "copilot" && (
              <div className="mc-copilot-container">
                <div className="mc-chips">
                  {COPILOT_CHIPS.map((c) => (
                    <span
                      key={c}
                      className="mc-chip"
                      onClick={() => handleAskCopilot(c)}
                    >
                      {c}
                    </span>
                  ))}
                </div>

                <div className="mc-chat-history">
                  {chatHistory.map((m, idx) => (
                    <div key={idx} className={`mc-chat-bubble ${m.role}`}>
                      <div className="mc-chat-meta">
                        <span>{m.role === "user" ? "Analyst" : "Copilot"}</span>
                        <span>{m.time || ""}</span>
                      </div>
                      <div style={{ whiteSpace: "pre-wrap" }}>{m.text}</div>
                      {m.latency && (
                        <div style={{ fontSize: 9, color: "#6f857a", marginTop: 4 }}>
                          {m.latency}ms · {m.model}
                        </div>
                      )}
                    </div>
                  ))}
                  {chatLoading && (
                    <div className="mc-chat-bubble copilot">
                      Querying SQLite telemetry, BDI snapshots, and findings...
                    </div>
                  )}
                </div>

                <form
                  className="mc-copilot-form"
                  onSubmit={(e) => {
                    e.preventDefault();
                    handleAskCopilot();
                  }}
                >
                  <input
                    type="text"
                    value={chatInput}
                    onChange={(e) => setChatInput(e.target.value)}
                    placeholder="Ask Copilot about current incidents..."
                  />
                  <button type="submit" className="on">
                    Ask
                  </button>
                </form>
              </div>
            )}

            {/* TAB 3: 30-MINUTE & ON-DEMAND POSTURE REPORTS */}
            {activeTab === "reports" && (
              <div>
                <div className="mc-rep-ctrl">
                  <select
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
                    className="on"
                    disabled={generatingReport}
                    onClick={handleGenerateReport}
                  >
                    {generatingReport ? "Generating..." : "Generate Report"}
                  </button>
                </div>

                {/* Filter Tabs between 30-min Posture Reports and Quarantine Remediation Plans */}
                <div style={{ display: "flex", gap: 6, marginBottom: 8, flexWrap: "wrap" }}>
                  <button
                    className={`mc-btn-sm ${reportFilter === "all" ? "on" : ""}`}
                    onClick={() => setReportFilter("all")}
                  >
                    All ({reports.length})
                  </button>
                  <button
                    className={`mc-btn-sm ${reportFilter === "posture" ? "on" : ""}`}
                    onClick={() => setReportFilter("posture")}
                  >
                    30m Posture ({reports.filter((r) => r.data?.type !== "remediation_plan" && !r.report_id?.startsWith("remed-")).length})
                  </button>
                  <button
                    className={`mc-btn-sm ${reportFilter === "remediation" ? "on" : ""}`}
                    onClick={() => setReportFilter("remediation")}
                  >
                    Remediation Plans ({reports.filter((r) => r.data?.type === "remediation_plan" || r.report_id?.startsWith("remed-")).length})
                  </button>
                </div>
                <div className="mc-muted" style={{ fontSize: 10, marginBottom: 10, lineHeight: 1.4 }}>
                  ℹ️ <b>Scheduled Posture Reports</b> auto-generate once every 30 minutes. <b>Remediation Plans</b> auto-generate dry-run containment rules whenever a host is quarantined.
                </div>

                {(() => {
                  const isRemed = (r) => (
                    r.data?.type === "remediation_plan" ||
                    r.report_id?.startsWith("remed-") ||
                    r.window_name?.startsWith("Remediation Plan")
                  );
                  const displayReports = reports.filter((r) => {
                    if (reportFilter === "posture") return !isRemed(r);
                    if (reportFilter === "remediation") return isRemed(r);
                    return true;
                  });

                  if (displayReports.length === 0) {
                    return (
                      <div className="mc-empty">
                        No reports matching filter &quot;{reportFilter}&quot;.
                      </div>
                    );
                  }

                  return displayReports.map((r, idx) => {
                    const isRem = isRemed(r);
                    return (
                      <div key={r.report_id || idx} className="mc-card">
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
                          <span className={`mc-score-badge ${r.threat_level || "NOMINAL"}`}>
                            {r.threat_level} · Score: {r.posture_score}/100
                          </span>
                        </div>
                        <div className="mc-muted" style={{ fontSize: 10, marginBottom: 8 }}>
                          {r.created_at} · ID: <code>{r.report_id}</code>
                        </div>
                        {isRem && (
                          <>
                            <div style={{ fontSize: 10, marginBottom: 6 }}>
                              {r.data?.rationale || ""}
                            </div>
                            <pre className="mc-pre">
                              {`${r.data?.iptables || ""}\n\n${r.data?.nftables || ""}`}
                            </pre>
                          </>
                        )}
                      {(() => {
                        const targetRun = r.run_id || activeRunId || "run-live";
                        const pdfUrl = `/api/runs/${encodeURIComponent(targetRun)}/reports/${encodeURIComponent(r.report_id)}/pdf`;
                        const filename = `${r.report_id || "report"}.pdf`;
                        return (
                          <div style={{ display: "flex", gap: 6, flexWrap: "wrap", marginTop: 4 }}>
                            <button
                              className="mc-btn-sm"
                              onClick={() =>
                                setExpandedReportIdx(expandedReportIdx === idx ? null : idx)
                              }
                            >
                              {expandedReportIdx === idx
                                ? "Hide Document ▲"
                                : "View Text Document ▼"}
                            </button>
                            <button
                              className="mc-btn-sm on"
                              onClick={() => setPdfModalReport(r)}
                              title="Open live in-browser PDF previewer"
                            >
                              <span>📄</span> View PDF (Preview)
                            </button>
                            <a
                              className="mc-btn-sm"
                              href={pdfUrl}
                              download={filename}
                              style={{ textDecoration: "none", display: "inline-flex", alignItems: "center", gap: 4 }}
                              title="Download PDF directly"
                            >
                              <span>⬇</span> Download
                            </a>
                            <a
                              className="mc-btn-sm"
                              href={pdfUrl}
                              target="_blank"
                              rel="noopener noreferrer"
                              style={{ textDecoration: "none", display: "inline-flex", alignItems: "center", gap: 4 }}
                              title="Open in new browser tab"
                            >
                              <span>⤢</span> Tab
                            </a>
                          </div>
                        );
                      })()}
                      {expandedReportIdx === idx && (
                        <div className="mc-rep-doc" style={{ whiteSpace: "pre-wrap" }}>
                          {r.summary_md}
                        </div>
                      )}
                    </div>
                  );
                });
              })()}
            </div>
          )}

            {/* TAB 4: INCIDENTS & PENDING L3 QUARANTINE APPROVALS */}
            {activeTab === "incidents" && (
              <div>
                {quarantines.filter((q) => q.status === "PENDING").length > 0 && (
                  <div style={{ marginBottom: 12 }}>
                    <div
                      style={{
                        marginBottom: 6,
                        color: "#ff9a3c",
                        fontSize: 11,
                        fontWeight: "bold",
                      }}
                    >
                      Pending Quarantine Approvals (L3 Gate):
                    </div>
                    {quarantines
                      .filter((q) => q.status === "PENDING")
                      .map((q) => (
                        <div
                          key={q.quarantine_id}
                          className="mc-card"
                          style={{ borderLeft: "3px solid #ff9a3c" }}
                        >
                          <div
                            style={{
                              display: "flex",
                              justifyContent: "space-between",
                              alignItems: "center",
                            }}
                          >
                            <div>
                              <b>{q.host_id}</b> · <code>{q.rule_id}</code>
                              <div className="mc-muted" style={{ fontSize: 10 }}>
                                conf: {q.confidence} · remote_exploitable:{" "}
                                {q.remote_exploitable ? "yes" : "no"} · {q.finding_id}
                              </div>
                            </div>
                            <div style={{ display: "flex", gap: 6 }}>
                              <button
                                className="mc-btn-sm on"
                                onClick={() =>
                                  handleQuarantineDecide(q.quarantine_id, "APPROVED")
                                }
                              >
                                Approve
                              </button>
                              <button
                                className="mc-btn-sm"
                                onClick={() =>
                                  handleQuarantineDecide(q.quarantine_id, "REJECTED")
                                }
                              >
                                Reject
                              </button>
                            </div>
                          </div>
                        </div>
                      ))}
                  </div>
                )}

                {incidents.length === 0 ? (
                  <div className="mc-empty">No active security incidents correlated yet.</div>
                ) : (
                  incidents.map((inc, idx) => (
                    <div key={inc.incident_id || idx} className="mc-card">
                      <div
                        style={{
                          display: "flex",
                          justifyContent: "space-between",
                          alignItems: "center",
                          marginBottom: 4,
                        }}
                      >
                        <div>
                          <span
                            className="mc-tag"
                            style={{
                              color:
                                inc.severity === "CRITICAL"
                                  ? "#ff4d5e"
                                  : inc.severity === "HIGH"
                                  ? "#ff9a3c"
                                  : "#f5d547",
                            }}
                          >
                            {inc.severity}
                          </span>
                          <b>{inc.incident_id}</b>: {inc.host_id}
                        </div>
                        <span
                          className={`mc-score-badge ${
                            inc.quarantined ? "CRITICAL" : "ELEVATED"
                          }`}
                        >
                          {inc.quarantined ? "CONTAINED" : "ACTIVE THREAT"}
                        </span>
                      </div>
                      <div style={{ fontSize: 11, margin: "4px 0" }}>{inc.title}</div>
                      {inc.cves?.length > 0 && (
                        <div className="mc-muted" style={{ fontSize: 10 }}>
                          CVEs: {inc.cves.join(", ")}
                        </div>
                      )}
                      <div className="mc-muted" style={{ fontSize: 10, marginTop: 4 }}>
                        {inc.summary}
                      </div>
                    </div>
                  ))
                )}
              </div>
            )}

            {/* TAB 5: CONTRACT-NET NEGOTIATION */}
            {activeTab === "neg" && (
              <div>
                {derived.msgEvents.filter((m) => NEG_SET.has(m.performative)).length ===
                0 ? (
                  <div className="mc-empty">No negotiation messages yet.</div>
                ) : (
                  derived.msgEvents
                    .filter((m) => NEG_SET.has(m.performative))
                    .slice(-80)
                    .reverse()
                    .map((m, idx) => {
                      const c = PCOL[m.performative] || "#5dff9d";
                      return (
                        <div
                          key={idx}
                          className="mc-row"
                          onClick={() => {
                            setSelectedEventIdx(m.evIndex);
                            setActiveTab("agent");
                          }}
                        >
                          <span className="mc-tag" style={{ color: c }}>
                            {m.performative}
                          </span>
                          <span>
                            <b>
                              {m.sender} → {m.receiver}
                            </b>
                            <div className="mc-muted">
                              {JSON.stringify(m.payload).slice(0, 140)}
                            </div>
                          </span>
                        </div>
                      );
                    })
                )}
              </div>
            )}

            {/* TAB 6: FLEET TILES */}
            {activeTab === "fleet" && (
              <div className="mc-fleet">
                {(() => {
                  const hosts = {};
                  devices.forEach((r) => {
                    const h = (hosts[r.host_id] ??= {
                      id: r.host_id,
                      ip: r.ip,
                      svc: new Set(),
                      poisoned: false,
                    });
                    h.svc.add(`${r.service}:${r.port}`);
                    h.poisoned = h.poisoned || r.is_poisoned;
                  });
                  const list = Object.values(hosts).sort(
                    (a, b) =>
                      derived.quarantinedHosts.has(b.id) -
                        derived.quarantinedHosts.has(a.id) ||
                      b.poisoned - a.poisoned ||
                      a.id.localeCompare(b.id)
                  );
                  if (list.length === 0) {
                    return <div className="mc-empty">No devices registered yet.</div>;
                  }
                  return list.map((h) => {
                    const isQ = derived.quarantinedHosts.has(h.id);
                    const fc = findings.filter((f) => f.host_id === h.id).length;
                    return (
                      <div
                        key={h.id}
                        className={`mc-tile ${isQ ? "q" : ""} ${h.poisoned ? "p" : ""}`}
                      >
                        <em />
                        <b>{h.id}</b>
                        <div className="mc-muted">{h.ip}</div>
                        <div className="mc-muted">{[...h.svc].join(" ")}</div>
                        <div>
                          {fc} findings{" "}
                          {isQ && <b style={{ color: "#ff4d5e" }}>QUARANTINED</b>}{" "}
                          {h.poisoned && (
                            <span style={{ color: "#f5d547" }}>poisoned</span>
                          )}
                        </div>
                      </div>
                    );
                  });
                })()}
              </div>
            )}

            {/* TAB 7: FINDINGS */}
            {activeTab === "find" && (
              <div>
                {findings.length === 0 ? (
                  <div className="mc-empty">No findings detected yet.</div>
                ) : (
                  [...findings]
                    .sort((a, b) => {
                      const rank = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
                      return (rank[a.severity] ?? 9) - (rank[b.severity] ?? 9);
                    })
                    .slice(0, 100)
                    .map((f, idx) => (
                      <div key={f.finding_id || idx} className="mc-card">
                        <span className={`mc-sev ${f.severity}`}>{f.severity}</span>{" "}
                        <b>{f.rule_id}</b> {f.cve_id || ""}
                        <div className="mc-muted" style={{ marginTop: 3 }}>
                          {f.host_id} · conf {f.confidence}{" "}
                          {f.quarantined && (
                            <b style={{ color: "#ff4d5e" }}>· quarantined</b>
                          )}
                        </div>
                      </div>
                    ))
                )}
              </div>
            )}

            {/* TAB 8: LIVE EVENT LOG */}
            {activeTab === "log" && (
              <div>
                {derived.slice.length === 0 ? (
                  <div className="mc-empty">No events yet.</div>
                ) : (
                  derived.slice
                    .slice(-150)
                    .reverse()
                    .map((e, idx) => (
                      <div
                        key={e.seq || idx}
                        className={`mc-row ${e.status === "REJECTED" ? "rej" : ""}`}
                        onClick={() => {
                          setSelectedEventIdx(events.indexOf(e));
                          setActiveTab("agent");
                        }}
                      >
                        <span className="mc-muted">#{e.seq}</span>
                        <span>
                          {e.event_type}{" "}
                          <span className="mc-muted">
                            {norm(e.component)}
                            {e.details?.receiver
                              ? ` → ${norm(e.details.receiver)}`
                              : ""}{" "}
                            {e.reason_code || ""}
                          </span>
                        </span>
                      </div>
                    ))
                )}
              </div>
            )}
          </div>
        </aside>
      </div>

      {pdfModalReport && (
        <PdfViewerModal
          report={pdfModalReport}
          runId={activeRunId}
          onClose={() => setPdfModalReport(null)}
        />
      )}
    </div>
  );
}
