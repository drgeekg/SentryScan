import React from "react";

export default function PdfViewerModal({ report, runId, onClose }) {
  if (!report) return null;
  const targetRun = report.run_id || runId || "run-live";
  const reportId = report.report_id || "posture-report";
  const pdfUrl = `/api/runs/${encodeURIComponent(targetRun)}/reports/${encodeURIComponent(reportId)}/pdf`;
  const filename = `${reportId}.pdf`;

  return (
    <div className="soc-modal-overlay" onClick={onClose}>
      <div className="soc-modal-card" onClick={(e) => e.stopPropagation()}>
        <div className="soc-modal-header">
          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <span style={{ fontSize: 22 }}>📄</span>
            <div>
              <div style={{ fontWeight: 700, fontSize: 13.5, color: "var(--text-main)" }}>
                {report.window_name || "Executive Posture Report"}
              </div>
              <div style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 2 }}>
                Report ID: <code style={{ color: "var(--accent-cyan)" }}>{reportId}</code> · Score: <strong>{report.posture_score}/100</strong> · Threat: {report.threat_level || "NOMINAL"}
              </div>
            </div>
          </div>
          <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
            <a
              className="soc-btn"
              href={pdfUrl}
              download={filename}
              title="Download PDF directly to your device"
            >
              ⬇ Download
            </a>
            <a
              className="soc-btn"
              href={pdfUrl}
              target="_blank"
              rel="noopener noreferrer"
              title="Open PDF in a new browser tab"
            >
              ⤢ New Tab
            </a>
            <button
              className="soc-btn"
              onClick={onClose}
              style={{ fontWeight: 800, padding: "4px 9px", cursor: "pointer" }}
            >
              ✕
            </button>
          </div>
        </div>
        <div className="soc-modal-body">
          <iframe
            src={pdfUrl}
            title={reportId}
            width="100%"
            height="100%"
            style={{ border: "none", width: "100%", height: "100%" }}
          />
        </div>
      </div>
    </div>
  );
}
