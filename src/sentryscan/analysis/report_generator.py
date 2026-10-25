"""Posture Report Generator, Incident Correlation & SOC Copilot Q&A Engine."""

from __future__ import annotations

import io
import json
import re
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from sentryscan.common.clock import SystemClock
from sentryscan.llm.factory import get_llm_provider
from sentryscan.llm.interface import LLMProvider, LLMRequest
from sentryscan.storage.store import SQLiteRunStore


def correlate_incidents(findings: list[dict[str, Any]], quarantined_hosts: set[str]) -> list[dict[str, Any]]:
    """Group individual findings by host into coherent Security Incidents."""
    by_host: dict[str, list[dict[str, Any]]] = {}
    for f in findings:
        h = f.get("host_id", "unknown")
        by_host.setdefault(h, []).append(f)

    rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
    incidents = []

    for idx, (host, f_list) in enumerate(sorted(by_host.items()), 1):
        max_sev = max(f_list, key=lambda x: rank.get(str(x.get("severity", "LOW")).upper(), 0)).get("severity", "LOW")
        cves = [f.get("cve_id") for f in f_list if f.get("cve_id")]
        rules = [f.get("rule_id") for f in f_list if f.get("rule_id")]
        is_q = host in quarantined_hosts

        title = f"Multi-vector Compromise on {host}" if len(f_list) > 1 else f"Exposure Detection on {host}"
        if cves:
            title += f" ({', '.join(filter(None, set(cves)))})"

        incidents.append({
            "incident_id": f"INC-{idx:03d}",
            "title": title,
            "host_id": host,
            "severity": max_sev,
            "status": "CONTAINED" if is_q else "ACTIVE_THREAT",
            "findings_count": len(f_list),
            "cves": list(set(filter(None, cves))),
            "rules": list(set(filter(None, rules))),
            "quarantined": is_q,
            "summary": f"{len(f_list)} findings detected. Status: {'Quarantined by BDI Analyst' if is_q else 'Monitoring / Pending Containment'}.",
        })

    incidents.sort(key=lambda x: rank.get(str(x["severity"]).upper(), 0), reverse=True)
    return incidents


def generate_posture_report(
    store: SQLiteRunStore,
    run_id: str,
    window_name: str = "Last 30 Minutes",
    llm: LLMProvider | None = None,
) -> dict[str, Any]:
    """Generate and persist a comprehensive SOC Posture & Incident Report."""
    provider = llm or get_llm_provider(purpose="report")
    clk = SystemClock()
    now_iso = clk.now_iso()
    t0 = time.perf_counter()

    all_findings = store.get_findings(run_id)
    all_records = store.get_telemetry_records(run_id)
    devices = {r["host_id"] for r in all_records}

    w_low = window_name.lower()
    minutes: int | None = None
    if "15" in w_low:
        minutes = 15
    elif "30" in w_low:
        minutes = 30
    elif "1 hour" in w_low or "60" in w_low:
        minutes = 60

    if minutes is not None:
        cutoff_iso = (datetime.now(timezone.utc) - timedelta(minutes=minutes)).isoformat().replace("+00:00", "Z")
        findings = [f for f in all_findings if str(f.get("timestamp_utc", "")) >= cutoff_iso] or all_findings
        records = [r for r in all_records if str(r.get("generated_at", "")) >= cutoff_iso] or all_records
    else:
        findings = all_findings
        records = all_records
    quarantined = {f["host_id"] for f in findings if f.get("quarantined")}
    bdi_snaps = store.get_bdi_snapshots(run_id)
    latest_bdi = bdi_snaps[-1] if bdi_snaps else {}

    crit_count = sum(1 for f in findings if str(f.get("severity")).upper() == "CRITICAL")
    high_count = sum(1 for f in findings if str(f.get("severity")).upper() == "HIGH")
    med_count = sum(1 for f in findings if str(f.get("severity")).upper() == "MEDIUM")
    low_count = sum(1 for f in findings if str(f.get("severity")).upper() == "LOW")

    penalty = (crit_count * 15) + (high_count * 7) + (med_count * 2) + (len(quarantined) * 5)
    score = max(10, min(100, 100 - penalty))

    threat_level = "CRITICAL" if score < 45 or crit_count > 0 else "ELEVATED" if score < 80 or high_count > 0 else "NOMINAL"

    incidents = correlate_incidents(findings, quarantined)
    report_id = f"rep-{int(time.time()):08d}-{uuid.uuid4().hex[:4]}"

    llm_prompt = (
        f"Generate executive posture summary for window '{window_name}'. "
        f"Score: {score}/100, Threat: {threat_level}. Findings: {len(findings)} "
        f"(Crit:{crit_count}, High:{high_count}). Quarantined: {len(quarantined)}/{len(devices)}."
    )
    req = LLMRequest(
        role="posture_report",
        system="You are SentryScan VIGIL SOC Executive Reporter.",
        messages=[{"role": "user", "content": llm_prompt}],
        request_id=report_id,
    )
    resp = provider.generate(req)
    latency_ms = round((time.perf_counter() - t0) * 1000, 1)

    md_lines = [
        "# SentryScan // VIGIL Executive Posture & Incident Report",
        f"**Period:** {window_name} | **Generated:** {now_iso} | **Report ID:** `{report_id}`",
        "",
        "---",
        "",
        "## 1. Executive Summary",
        f"- **Threat Posture:** `{threat_level}`",
        f"- **Security Posture Score:** **{score} / 100**",
        f"- **Fleet Monitored:** {len(devices)} endpoints",
        f"- **Active Quarantined Assets:** {len(quarantined)} hosts",
        f"- **Advisory:** {resp.text}",
        "",
        "## 2. Telemetry & Vulnerability Metrics",
        "| Metric | Value |",
        "|---|---|",
        f"| Total Telemetry Records Analyzed | {len(records)} |",
        f"| Critical Vulnerabilities | {crit_count} |",
        f"| High Severity Findings | {high_count} |",
        f"| Medium Severity Findings | {med_count} |",
        f"| Active Correlated Incidents | {len(incidents)} |",
        "",
        "## 3. Correlated Incidents",
    ]

    if incidents:
        for inc in incidents[:6]:
            cve_str = f" [CVEs: {', '.join(inc['cves'])}]" if inc["cves"] else ""
            status_tag = "**[QUARANTINED]**" if inc["quarantined"] else "*[ACTIVE]*"
            md_lines.append(f"- **{inc['incident_id']}** ({inc['severity']}): `{inc['host_id']}` {status_tag} - {inc['title']}{cve_str}")
    else:
        md_lines.append("*No security incidents detected in this window.*")

    md_lines.extend([
        "",
        "## 4. Analyst BDI Containment Status",
        f"- **Active Intention:** `{latest_bdi.get('intention_type', 'CONTAIN_COMPROMISED_HOSTS')}`",
        f"- **Desire Objective:** `{latest_bdi.get('desire_type', 'CONTAIN_COMPROMISED_HOSTS')}`",
        f"- **Target Asset:** `{latest_bdi.get('target_host', 'none')}`",
        "",
        "## 5. Prioritized Remediation Actions",
        f"1. **Isolate Compromised Hosts:** Enforce firewall blocks on {', '.join(quarantined) if quarantined else 'none'}.",
        "2. **Patch Vulnerable Daemons:** Upgrade Apache HTTP server (CVE-2021-41773) and vsftpd 2.3.4.",
        "3. **Decommission Cleartext Protocols:** Terminate open Telnet and anonymous FTP listeners across IoT and legacy workstations.",
    ])

    summary_md = "\n".join(md_lines)
    data = {
        "report_id": report_id,
        "run_id": run_id,
        "created_at": now_iso,
        "window_name": window_name,
        "score": score,
        "posture_score": score,
        "threat_level": threat_level,
        "report_type": "posture_report",
        "metrics": {
            "telemetry_count": len(records),
            "findings_count": len(findings),
            "critical": crit_count,
            "high": high_count,
            "medium": med_count,
            "quarantined": len(quarantined),
            "fleet_size": len(devices),
        },
        "incidents": incidents,
        "latency_ms": latency_ms,
    }

    store.save_report(
        report_id=report_id,
        run_id=run_id,
        created_at=now_iso,
        window_name=window_name,
        posture_score=score,
        threat_level=threat_level,
        summary_md=summary_md,
        data_json=json.dumps(data),
    )
    store.save_llm_call(
        call_id=f"llm-{uuid.uuid4().hex[:8]}",
        run_id=run_id,
        provider="deterministic",
        model=resp.model,
        role="posture_report",
        prompt_excerpt=llm_prompt[:200],
        response_excerpt=resp.text[:300],
        tokens=resp.tokens_in + resp.tokens_out,
        latency_ms=latency_ms,
        timestamp_utc=now_iso,
    )

    data["summary_md"] = summary_md
    return data


def ask_soc_copilot(
    store: SQLiteRunStore,
    run_id: str,
    question: str,
    llm: LLMProvider | None = None,
) -> dict[str, Any]:
    """Answer analyst questions grounded in real-time SOC state."""
    provider = llm or get_llm_provider(purpose="copilot")
    t0 = time.perf_counter()
    clk = SystemClock()
    now_iso = clk.now_iso()

    findings = store.get_findings(run_id)
    records = store.get_telemetry_records(run_id)
    quarantined = sorted({f["host_id"] for f in findings if f.get("quarantined")})
    bdi = store.get_bdi_snapshots(run_id)
    latest_bdi = bdi[-1] if bdi else {}
    q_lower = question.lower()

    crit_findings = [f for f in findings if str(f.get("severity")).upper() == "CRITICAL"]
    cves = sorted({f["cve_id"] for f in findings if f.get("cve_id")})

    is_remote = hasattr(provider, "client") or getattr(provider, "provider", "") not in ("deterministic", "fake")
    model_name = getattr(provider, "model", getattr(provider, "model_name", "sentryscan-llm"))

    if is_remote:
        context_prompt = (
            f"Real-time SOC Telemetry & Defense State:\n"
            f"- Monitored endpoints: {len({r['host_id'] for r in records})}\n"
            f"- Quarantined hosts ({len(quarantined)}): {', '.join(quarantined) if quarantined else 'None'}\n"
            f"- Total findings: {len(findings)} (Critical: {len(crit_findings)})\n"
            f"- Active CVEs: {', '.join(cves) if cves else 'None'}\n"
            f"- Analyst Intention: {latest_bdi.get('intention_type', 'CONTAIN_COMPROMISED_HOSTS')} targeting {latest_bdi.get('target_host', 'none')}"
        )
        req = LLMRequest(
            role="soc_copilot",
            system=(
                "You are an expert autonomous SOC Copilot Assistant for SentryScan VIGIL. "
                "Use the provided real-time SOC state to answer the analyst concisely and accurately. "
                "Highlight risk levels, quarantined hosts, and recommended containment steps."
            ),
            messages=[
                {"role": "system", "content": context_prompt},
                {"role": "user", "content": question},
            ],
            request_id=f"ask-{int(time.time())}",
        )
        llm_resp = provider.generate(req)
        ans = llm_resp.text
        model_name = getattr(llm_resp, "model", model_name)
    else:
        if "quarantin" in q_lower or "isolated" in q_lower:
            ans = (
                f"Currently, {len(quarantined)} host(s) are quarantined: **{', '.join(quarantined) if quarantined else 'None'}**. "
                f"Quarantine was enacted by the Analyst Agent (BDI Planner) following detection of high-risk "
                f"or critical severity exposures (such as Apache CVE-2021-41773). Isolated from routing until remediated."
            )
        elif "cve" in q_lower or "vulnerabilit" in q_lower or "threat" in q_lower:
            ans = (
                f"Detected **{len(findings)} findings** across the fleet, including {len(crit_findings)} CRITICAL exposures. "
                f"Active CVEs: **{', '.join(cves) if cves else 'None'}**."
            )
        elif "device" in q_lower or "fleet" in q_lower or "host" in q_lower:
            ans = f"Fleet simulator is monitoring **{len({r['host_id'] for r in records})} synthetic endpoints**."
        elif "agent" in q_lower or "bdi" in q_lower:
            ans = (
                f"Multi-agent team: Supervisor, ScoutAgent, TriageAgent, ScannerWorkers, and AnalystAgent (BDI). "
                f"Analyst Intention: `{latest_bdi.get('intention_type', 'CONTAIN_COMPROMISED_HOSTS')}`."
            )
        else:
            ans = f"Overall Posture: **{'CONTAINMENT ACTIVE' if quarantined else 'NOMINAL'}**. Analyzed {len(records)} records."

    latency_ms = round((time.perf_counter() - t0) * 1000, 1)

    store.save_llm_call(
        call_id=f"ask-{uuid.uuid4().hex[:8]}",
        run_id=run_id,
        provider=getattr(provider, "provider", "llm"),
        model=model_name,
        role="soc_qa",
        prompt_excerpt=question[:200],
        response_excerpt=ans[:300],
        tokens=len(question.split()) + len(ans.split()),
        latency_ms=latency_ms,
        timestamp_utc=now_iso,
    )

    return {
        "question": question,
        "answer": ans,
        "model": model_name,
        "latency_ms": latency_ms,
        "timestamp_utc": now_iso,
    }


def _build_minimal_pdf(report: dict[str, Any]) -> bytes:
    """Zero-dependency pure-Python PDF generator fallback for environments without reportlab."""
    window = report.get("window_name", "Last 30 Minutes")
    created = report.get("created_at", "")
    score = report.get("posture_score", 0)
    threat = report.get("threat_level", "NOMINAL")
    report_id = report.get("report_id", "REP-001")
    summary = report.get("summary_md", "")

    lines = [
        "SentryScan // VIGIL Executive Posture Report",
        f"Period: {window} | Generated: {created} | ID: {report_id}",
        f"Security Posture Score: {score}/100 | Threat Level: {threat}",
        "-" * 65,
    ]
    for raw_l in summary.split("\n"):
        clean = raw_l.replace("#", "").replace("**", "").replace("`", "").strip()
        if clean and not clean.startswith("---"):
            lines.append(clean[:78])

    content_stream = [
        "BT /F1 15 Tf 50 740 Td (" + lines[0].replace("(", "\\(").replace(")", "\\)") + ") Tj ET",
        "BT /F1 8.5 Tf 50 722 Td (" + lines[1].replace("(", "\\(").replace(")", "\\)") + ") Tj ET",
        "BT /F1 10 Tf 50 706 Td (" + lines[2].replace("(", "\\(").replace(")", "\\)") + ") Tj ET",
        "BT /F1 9 Tf 50 694 Td (" + lines[3].replace("(", "\\(").replace(")", "\\)") + ") Tj ET",
    ]

    y = 675
    for l in lines[4:40]:
        escaped = l.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
        content_stream.append(f"BT /F1 8.5 Tf 50 {y} Td ({escaped}) Tj ET")
        y -= 14
        if y < 50:
            break

    stream_data = "\n".join(content_stream).encode("latin1", "replace")
    stream_len = len(stream_data)

    pdf = bytearray()
    pdf.extend(b"%PDF-1.4\n")
    offsets = []

    def add_obj(data_bytes: bytes):
        offsets.append(len(pdf))
        pdf.extend(data_bytes)

    add_obj(b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n")
    add_obj(b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n")
    add_obj(b"3 0 obj\n<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 4 0 R >> >> /MediaBox [0 0 612 792] /Contents 5 0 R >>\nendobj\n")
    add_obj(b"4 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n")
    add_obj(f"5 0 obj\n<< /Length {stream_len} >>\nstream\n".encode("latin1") + stream_data + b"\nendstream\nendobj\n")

    xref_offset = len(pdf)
    pdf.extend(b"xref\n0 6\n0000000000 65535 f \n")
    for o in offsets:
        pdf.extend(f"{o:010d} 00000 n \n".encode("latin1"))
    pdf.extend(f"trailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n{xref_offset}\n%%EOF\n".encode("latin1"))

    return bytes(pdf)


def build_pdf_report(report: dict[str, Any]) -> bytes:
    """Generate professional PDF bytes from report dictionary using ReportLab with zero-dependency fallback."""
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import letter
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.pdfgen import canvas
        from reportlab.platypus import (
            Paragraph,
            Preformatted,
            SimpleDocTemplate,
            Spacer,
            Table,
            TableStyle,
        )
    except (ImportError, ModuleNotFoundError) as e:
        logger.warning("ReportLab not available (%s); generating pure-Python fallback PDF", e)
        return _build_minimal_pdf(report)

    class NumberedCanvas(canvas.Canvas):
        """Two-pass canvas adding running header, running footer, and dynamic total page count."""

        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self._saved_page_states = []

        def showPage(self):
            self._saved_page_states.append(dict(self.__dict__))
            self._startPage()

        def save(self):
            num_pages = len(self._saved_page_states)
            for state in self._saved_page_states:
                self.__dict__.update(state)
                self.draw_decorations(num_pages)
                super().showPage()
            super().save()

        def draw_decorations(self, page_count: int):
            self.saveState()
            # Top Running Header Banner
            self.setFont("Helvetica-Bold", 7.5)
            self.setFillColor(colors.HexColor("#475569"))
            self.drawString(36, 756, "SENTRYSCAN // AUTONOMOUS CYBER SOC PLATFORM")
            self.setFont("Helvetica-Bold", 7.5)
            self.setFillColor(colors.HexColor("#dc2626"))
            self.drawRightString(576, 756, "CONFIDENTIAL // RESTRICTED SOC OPERATOR ACCESS")
            self.setStrokeColor(colors.HexColor("#cbd5e1"))
            self.setLineWidth(0.75)
            self.line(36, 748, 576, 748)

            # Bottom Running Footer
            self.setStrokeColor(colors.HexColor("#cbd5e1"))
            self.setLineWidth(0.75)
            self.line(36, 45, 576, 45)
            self.setFont("Helvetica", 7.5)
            self.setFillColor(colors.HexColor("#64748b"))
            self.drawString(36, 32, "AUTONOMOUS AGENTIC CYBER PLATFORM · VIGIL · SENTRA · POLARIS")
            self.setFont("Helvetica-Bold", 7.5)
            self.drawRightString(576, 32, f"Page {self._pageNumber} of {page_count}")
            self.restoreState()

    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=letter,
        leftMargin=36,
        rightMargin=36,
        topMargin=54,
        bottomMargin=54,
    )
    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "DocTitle",
        parent=styles["Heading1"],
        fontName="Helvetica-Bold",
        fontSize=15,
        leading=18,
        textColor=colors.HexColor("#0f172a"),
    )
    sub_style = ParagraphStyle(
        "DocSub",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=8.5,
        leading=11,
        textColor=colors.HexColor("#475569"),
    )
    h2_style = ParagraphStyle(
        "DocH2",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=11,
        leading=14,
        textColor=colors.HexColor("#0f172a"),
        spaceBefore=12,
        spaceAfter=4,
    )
    body_style = ParagraphStyle(
        "DocBody",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9,
        leading=13,
        textColor=colors.HexColor("#1e293b"),
    )
    code_style = ParagraphStyle(
        "DocCode",
        parent=styles["Code"],
        fontName="Courier",
        fontSize=7.5,
        leading=9.5,
        textColor=colors.HexColor("#0f172a"),
        backColor=colors.HexColor("#f8fafc"),
    )
    th_style = ParagraphStyle(
        "TH",
        fontName="Helvetica-Bold",
        fontSize=8,
        leading=10,
        textColor=colors.white,
    )
    td_style = ParagraphStyle(
        "TD",
        fontName="Helvetica",
        fontSize=8,
        leading=10.5,
        textColor=colors.HexColor("#1e293b"),
    )

    story = []

    report_id = report.get("report_id", "REP-001")
    window_name = report.get("window_name", "Executive Posture Report")
    created_at = report.get("created_at", "")
    score = report.get("posture_score", 0)
    threat = str(report.get("threat_level", "NOMINAL")).upper()

    is_remed = "remediation" in window_name.lower() or report.get("data", {}).get("type") == "remediation_plan"
    header_title = "SentryScan // VIGIL Host Remediation Plan" if is_remed else "SentryScan // VIGIL Executive Posture Report"

    header_cell = [
        Paragraph(f"<b>{header_title}</b>", title_style),
        Paragraph(f"Period: <b>{window_name}</b> | Generated: {created_at} | ID: <code>{report_id}</code>", sub_style),
    ]
    threat_col = colors.HexColor("#dc2626") if threat in ("CRITICAL", "HIGH") else colors.HexColor("#f59e0b") if threat == "ELEVATED" else colors.HexColor("#16a34a")
    score_cell = [
        Paragraph(f"<font size=20><b>{score}</b></font>/100<br/><font size=7.5 color='#64748b'>SECURITY POSTURE</font>", ParagraphStyle("Score", alignment=1, leading=20)),
        Paragraph(f"<b>{threat}</b>", ParagraphStyle("Threat", alignment=1, textColor=threat_col, fontSize=9.5)),
    ]
    hdr_table = Table([[header_cell, score_cell]], colWidths=[390, 150])
    hdr_table.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LINEBELOW", (0, 0), (-1, -1), 1, colors.HexColor("#cbd5e1")),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ]))
    story.append(hdr_table)
    story.append(Spacer(1, 8))

    def _to_rl(text: str) -> str:
        t = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        t = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", t)
        t = re.sub(r"`(.+?)`", r'<font face="Courier">\1</font>', t)
        return t

    summary_md = report.get("summary_md", "")
    lines = summary_md.split("\n")
    idx = 0
    while idx < len(lines):
        line = lines[idx].strip()
        idx += 1
        if not line or line.startswith("---") or line.startswith("# "):
            continue

        # Table block parser
        if line.startswith("|") and "|" in line[1:]:
            table_lines = [line]
            while idx < len(lines) and lines[idx].strip().startswith("|"):
                table_lines.append(lines[idx].strip())
                idx += 1

            rows = []
            for t_line in table_lines:
                if "---" in t_line:
                    continue
                cells = [c.strip() for c in t_line.strip("|").split("|")]
                if not any(cells):
                    continue
                is_head = len(rows) == 0
                st = th_style if is_head else td_style
                rows.append([Paragraph(_to_rl(c), st) for c in cells])

            if rows:
                col_w = [540.0 / len(rows[0])] * len(rows[0])
                t_obj = Table(rows, colWidths=col_w)
                t_style = [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ("TOPPADDING", (0, 0), (-1, -1), 4),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                    ("LEFTPADDING", (0, 0), (-1, -1), 6),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ]
                for r_idx in range(1, len(rows)):
                    bg = colors.HexColor("#f8fafc") if r_idx % 2 == 1 else colors.white
                    t_style.append(("BACKGROUND", (0, r_idx), (-1, r_idx), bg))
                t_obj.setStyle(TableStyle(t_style))
                story.append(t_obj)
                story.append(Spacer(1, 6))
            continue

        if line.startswith("## "):
            story.append(Paragraph(_to_rl(line.replace("## ", "")), h2_style))
        elif line.startswith("### "):
            story.append(Paragraph(_to_rl(line.replace("### ", "")), h2_style))
        elif line.startswith("```"):
            continue
        elif line.startswith("- "):
            story.append(Paragraph(f"• {_to_rl(line[2:])}", body_style))
            story.append(Spacer(1, 2))
        else:
            story.append(Paragraph(_to_rl(line), body_style))
            story.append(Spacer(1, 3))

    data = report.get("data") or {}
    if isinstance(data, str):
        try:
            data = json.loads(data)
        except Exception:
            data = {}
    if data.get("iptables"):
        story.append(Spacer(1, 8))
        story.append(Paragraph("<b>iptables Containment Rules (Dry-Run Text):</b>", h2_style))
        story.append(Preformatted(data["iptables"], code_style))
    if data.get("nftables"):
        story.append(Spacer(1, 8))
        story.append(Paragraph("<b>nftables Containment Rules (Dry-Run Text):</b>", h2_style))
        story.append(Preformatted(data["nftables"], code_style))

    try:
        doc.build(story, canvasmaker=NumberedCanvas)
    except Exception as e:
        logger.warning("Rich ReportLab build failed (%s); building safe fallback PDF", e)
        buf = io.BytesIO()
        fallback_doc = SimpleDocTemplate(
            buf,
            pagesize=letter,
            leftMargin=36,
            rightMargin=36,
            topMargin=54,
            bottomMargin=54,
        )
        safe_story = [
            Paragraph(f"<b>{header_title}</b>", title_style),
            Spacer(1, 6),
            Paragraph(f"Period: {window_name} | Score: {score}/100 | Threat: {threat}", sub_style),
            Spacer(1, 10),
            Preformatted(report.get("summary_md", ""), code_style),
        ]
        fallback_doc.build(safe_story, canvasmaker=NumberedCanvas)

    return buf.getvalue()
