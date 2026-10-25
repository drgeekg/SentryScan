import React, { useState, useEffect } from "react";

export default function SimulationToolboxModal({ runId, onClose, onSuccess }) {
  const [injecting, setInjecting] = useState(false);
  const [status, setStatus] = useState(null);
  const [devices, setDevices] = useState([]);

  // Form states
  const [targetHost, setTargetHost] = useState("");
  const [preset, setPreset] = useState("apache_cve");
  const [recordCount, setRecordCount] = useState(5);
  const [poisonRate, setPoisonRate] = useState(0.0);
  const [customService, setCustomService] = useState("http");
  const [customPort, setCustomPort] = useState(80);
  const [customBanner, setCustomBanner] = useState("Apache/2.4.49 (Unix)");
  const [quarImmediate, setQuarImmediate] = useState(false);

  // Tuner states
  const [simPace, setSimPace] = useState(0.5);
  const [simPoison, setSimPoison] = useState(0.2);
  const [simProfile, setSimProfile] = useState("enterprise");

  // Quarantine target
  const [quarTarget, setQuarTarget] = useState("");

  const targetRun = runId || "run-live";

  useEffect(() => {
    fetch(`/api/runs/${encodeURIComponent(targetRun)}/devices`)
      .then((r) => (r.ok ? r.json() : []))
      .then((d) => {
        const list = Array.isArray(d) ? d : d.devices || [];
        setDevices(list);
        if (list.length > 0 && !targetHost) {
          setTargetHost(list[0].host_id);
          setQuarTarget(list[0].host_id);
        }
      })
      .catch(() => {});
  }, [targetRun]);

  const handleInject = async (overridePreset) => {
    if (injecting) return;
    setInjecting(true);
    setStatus(null);
    const chosenPreset = overridePreset || preset;
    const body = {
      preset: chosenPreset,
      host_id: targetHost || "windows-workstation-03",
      record_count: recordCount,
      poison_rate: chosenPreset === "poison_storm" ? 1.0 : poisonRate,
      quarantine_immediate: quarImmediate,
      service: customService,
      port: customPort,
      banner: customBanner,
    };
    try {
      const res = await fetch(`/api/runs/${encodeURIComponent(targetRun)}/telemetry/inject`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      const data = await res.json();
      if (res.ok) {
        setStatus({
          type: "success",
          msg: `Injected ${data.records_injected} records on ${data.host_id} (Clean: ${data.clean_verified}, Rejected: ${data.poisoned_rejected}, Findings: ${data.findings_created})`,
        });
        if (onSuccess) onSuccess();
      } else {
        setStatus({ type: "error", msg: data.detail || "Injection failed." });
      }
    } catch (e) {
      setStatus({ type: "error", msg: e.message });
    } finally {
      setInjecting(false);
    }
  };

  const handleTune = async () => {
    try {
      const res = await fetch(`/api/runs/${encodeURIComponent(targetRun)}/simulation/tune`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          pace: simPace,
          poison_ratio: simPoison,
          profile: simProfile,
        }),
      });
      const data = await res.json();
      if (res.ok) {
        setStatus({
          type: "success",
          msg: `Simulation tuned: Pace ${simPace}s · Poison ${Math.round(simPoison * 100)}% · Profile: ${simProfile}`,
        });
        if (onSuccess) onSuccess();
      }
    } catch (e) {
      setStatus({ type: "error", msg: e.message });
    }
  };

  const handleQuarantine = async (action) => {
    if (!quarTarget) return;
    try {
      const res = await fetch(`/api/runs/${encodeURIComponent(targetRun)}/hosts/${quarTarget}/quarantine`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          action,
          reason: "Manual operator override from Threat Toolbox modal",
        }),
      });
      const data = await res.json();
      if (res.ok) {
        setStatus({
          type: "success",
          msg: `Host ${quarTarget} ${action === "isolate" ? "QUARANTINED" : "RELEASED"} successfully.`,
        });
        if (onSuccess) onSuccess();
      }
    } catch (e) {
      setStatus({ type: "error", msg: e.message });
    }
  };

  return (
    <div className="soc-modal-overlay" onClick={onClose}>
      <div
        className="soc-modal-card"
        style={{ maxWidth: 840, maxHeight: "90vh", display: "flex", flexDirection: "column" }}
        onClick={(e) => e.stopPropagation()}
      >
        <div className="soc-modal-header">
          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <span style={{ fontSize: 22 }}>⚡</span>
            <div>
              <div style={{ fontWeight: 700, fontSize: 14, color: "var(--text-main)" }}>
                Simulation Control &amp; Threat Injection Toolbox
              </div>
              <div style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 2 }}>
                Inject attacks, trigger CVE rule matches, test integrity screening, tune live pace, or enforce quarantine.
              </div>
            </div>
          </div>
          <button
            className="soc-btn"
            onClick={onClose}
            style={{ fontWeight: 800, padding: "4px 9px", cursor: "pointer" }}
          >
            ✕
          </button>
        </div>

        <div className="soc-modal-body" style={{ padding: 20, overflowY: "auto" }}>
          {status && (
            <div
              style={{
                marginBottom: 16,
                padding: "8px 12px",
                borderRadius: 4,
                fontSize: 12,
                background: status.type === "success" ? "rgba(93,255,157,.12)" : "rgba(255,77,94,.12)",
                color: status.type === "success" ? "#5dff9d" : "#ff4d5e",
                border: `1px solid ${status.type === "success" ? "#5dff9d" : "#ff4d5e"}`,
              }}
            >
              {status.msg}
            </div>
          )}

          {/* SECTION 1: ONE-CLICK QUICK THREATS */}
          <div style={{ marginBottom: 20 }}>
            <div style={{ fontSize: 12, fontWeight: 700, color: "#f5d547", textTransform: "uppercase", marginBottom: 8 }}>
              1. One-Click Threat &amp; Telemetry Injections
            </div>
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 8 }}>
              <button
                className="mc-tool-action-btn crit"
                disabled={injecting}
                onClick={() => handleInject("apache_cve")}
              >
                <span>🔴</span>
                <div>
                  <b>Exploit: Apache 2.4.49 (CVE-2021-41773)</b>
                  <small>Matches RULE-005 (CRITICAL) → Escalates to L3 &amp; Auto-Quarantines</small>
                </div>
              </button>

              <button
                className="mc-tool-action-btn crit"
                disabled={injecting}
                onClick={() => handleInject("default_creds")}
              >
                <span>🔴</span>
                <div>
                  <b>Exploit: Default Admin Credentials (admin/admin)</b>
                  <small>Matches RULE-004 (CRITICAL) on Admin Portal Port 8080</small>
                </div>
              </button>

              <button
                className="mc-tool-action-btn high"
                disabled={injecting}
                onClick={() => handleInject("telnet_leak")}
              >
                <span>🟡</span>
                <div>
                  <b>Exposure: Cleartext Telnet Management</b>
                  <small>Matches RULE-001 (HIGH) on port 23 cleartext stream</small>
                </div>
              </button>

              <button
                className="mc-tool-action-btn poison"
                disabled={injecting}
                onClick={() => handleInject("poison_storm")}
              >
                <span>🟠</span>
                <div>
                  <b>Attack: Poisoned Telemetry Storm (100% Corrupted)</b>
                  <small>Tests Integrity Checker screening: contradictions, drift, replay</small>
                </div>
              </button>

              <button
                className="mc-tool-action-btn nominal"
                style={{ gridColumn: "span 2" }}
                disabled={injecting}
                onClick={() => handleInject("normal_traffic")}
              >
                <span>🟢</span>
                <div>
                  <b>Traffic: Clean Benign Telemetry Burst (20 records)</b>
                  <small>Tests high-speed flow: Fleet Sensor → Integrity Checker → Scanner</small>
                </div>
              </button>
            </div>
          </div>

          {/* 2 COLUMNS: TUNER & QUARANTINE */}
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16, marginBottom: 20 }}>
            {/* TUNER */}
            <div className="soc-card" style={{ padding: 14 }}>
              <div style={{ fontSize: 12, fontWeight: 700, color: "#4da3ff", textTransform: "uppercase", marginBottom: 8 }}>
                2. Live Simulation Dynamics
              </div>
              <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
                <div>
                  <div style={{ display: "flex", justifyContent: "space-between", fontSize: 11, marginBottom: 4 }}>
                    <span style={{ color: "var(--text-muted)" }}>Simulation Pace:</span>
                    <b>{simPace}s / cycle {simPace <= 0.2 ? "(Super Fast)" : simPace >= 1.5 ? "(Slow)" : ""}</b>
                  </div>
                  <input
                    type="range"
                    min="0.1"
                    max="2.5"
                    step="0.1"
                    value={simPace}
                    onChange={(e) => setSimPace(parseFloat(e.target.value))}
                    style={{ width: "100%" }}
                  />
                </div>

                <div>
                  <div style={{ display: "flex", justifyContent: "space-between", fontSize: 11, marginBottom: 4 }}>
                    <span style={{ color: "var(--text-muted)" }}>Poison Ratio:</span>
                    <b>{Math.round(simPoison * 100)}%</b>
                  </div>
                  <input
                    type="range"
                    min="0.0"
                    max="0.8"
                    step="0.05"
                    value={simPoison}
                    onChange={(e) => setSimPoison(parseFloat(e.target.value))}
                    style={{ width: "100%" }}
                  />
                </div>

                <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
                  <select
                    className="soc-select"
                    value={simProfile}
                    onChange={(e) => setSimProfile(e.target.value)}
                    style={{ flex: 1 }}
                  >
                    <option value="enterprise">Enterprise (Standard)</option>
                    <option value="soc_heavy">SOC Heavy (High Volume)</option>
                    <option value="stealth">Stealth (Low &amp; Slow)</option>
                  </select>
                  <button className="soc-btn soc-btn-primary" onClick={handleTune}>
                    ⚙ Apply
                  </button>
                </div>
              </div>
            </div>

            {/* MANUAL QUARANTINE */}
            <div className="soc-card" style={{ padding: 14 }}>
              <div style={{ fontSize: 12, fontWeight: 700, color: "#ff4d5e", textTransform: "uppercase", marginBottom: 8 }}>
                3. Asset Quarantine Control
              </div>
              <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
                <select
                  className="soc-select"
                  value={quarTarget}
                  onChange={(e) => setQuarTarget(e.target.value)}
                  style={{ width: "100%" }}
                >
                  <option value="">-- Select Host Asset --</option>
                  {devices.map((d) => (
                    <option key={d.host_id} value={d.host_id}>
                      {d.host_id}
                    </option>
                  ))}
                </select>

                <div style={{ display: "flex", gap: 8, marginTop: 4 }}>
                  <button
                    className="soc-btn"
                    style={{ flex: 1, background: "rgba(255,77,94,.18)", color: "#ff4d5e", border: "1px solid #ff4d5e" }}
                    disabled={!quarTarget}
                    onClick={() => handleQuarantine("isolate")}
                  >
                    🛑 Isolate Host
                  </button>
                  <button
                    className="soc-btn"
                    style={{ flex: 1, background: "rgba(93,255,157,.18)", color: "#5dff9d", border: "1px solid #5dff9d" }}
                    disabled={!quarTarget}
                    onClick={() => handleQuarantine("release")}
                  >
                    🟢 Release
                  </button>
                </div>
              </div>
            </div>
          </div>

          {/* CUSTOM BUILDER */}
          <div className="soc-card" style={{ padding: 14 }}>
            <div style={{ fontSize: 12, fontWeight: 700, color: "#5dff9d", textTransform: "uppercase", marginBottom: 8 }}>
              4. Custom Telemetry &amp; Vulnerability Percept Builder
            </div>
            <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
              <div style={{ display: "flex", gap: 8 }}>
                <input
                  type="text"
                  className="soc-input"
                  placeholder="Target Host ID (or random)"
                  value={targetHost}
                  onChange={(e) => setTargetHost(e.target.value)}
                  style={{ flex: 2 }}
                />
                <input
                  type="number"
                  className="soc-input"
                  placeholder="Port"
                  value={customPort}
                  onChange={(e) => setCustomPort(parseInt(e.target.value) || 80)}
                  style={{ flex: 1 }}
                />
              </div>

              <div style={{ display: "flex", gap: 8 }}>
                <input
                  type="text"
                  className="soc-input"
                  placeholder="Service (http, ssh, ftp, telnet)"
                  value={customService}
                  onChange={(e) => setCustomService(e.target.value)}
                  style={{ flex: 1 }}
                />
                <input
                  type="text"
                  className="soc-input"
                  placeholder="Banner string..."
                  value={customBanner}
                  onChange={(e) => setCustomBanner(e.target.value)}
                  style={{ flex: 2 }}
                />
              </div>

              <div style={{ display: "flex", gap: 16 }}>
                <div style={{ flex: 1 }}>
                  <div style={{ display: "flex", justifyContent: "space-between", fontSize: 11, marginBottom: 4 }}>
                    <span style={{ color: "var(--text-muted)" }}>Batch Size: {recordCount}</span>
                  </div>
                  <input
                    type="range"
                    min="1"
                    max="30"
                    value={recordCount}
                    onChange={(e) => setRecordCount(parseInt(e.target.value))}
                    style={{ width: "100%" }}
                  />
                </div>

                <div style={{ flex: 1 }}>
                  <div style={{ display: "flex", justifyContent: "space-between", fontSize: 11, marginBottom: 4 }}>
                    <span style={{ color: "var(--text-muted)" }}>Poison: {Math.round(poisonRate * 100)}%</span>
                  </div>
                  <input
                    type="range"
                    min="0"
                    max="1"
                    step="0.1"
                    value={poisonRate}
                    onChange={(e) => setPoisonRate(parseFloat(e.target.value))}
                    style={{ width: "100%" }}
                  />
                </div>
              </div>

              <button
                className="soc-btn soc-btn-primary"
                disabled={injecting}
                onClick={() => handleInject("custom")}
                style={{ marginTop: 6 }}
              >
                {injecting ? "Injecting Telemetry..." : "🚀 Inject Telemetry Batch"}
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
