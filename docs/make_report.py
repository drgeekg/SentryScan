from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.lib.units import mm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak

ss = getSampleStyleSheet()
H1 = ParagraphStyle("h1", parent=ss["Heading1"], textColor=colors.HexColor("#0b0f14"), spaceBefore=14)
H2 = ParagraphStyle("h2", parent=ss["Heading2"], textColor=colors.HexColor("#b36b00"))
B = ParagraphStyle("b", parent=ss["BodyText"], leading=15)
T = ParagraphStyle("t", parent=ss["Title"], fontSize=32)
C = ParagraphStyle("c", parent=B, fontSize=8.5, leading=11)


def tbl(rows, widths):
    rows = [[Paragraph(str(c), C) for c in r] for r in rows]
    t = Table(rows, colWidths=widths, repeatRows=1)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e8edf3")),
        ("GRID", (0, 0), (-1, -1), .4, colors.HexColor("#b0b8c4")),
        ("VALIGN", (0, 0), (-1, -1), "TOP")]))
    return t


def bullets(items):
    return [Paragraph("• " + i, B) for i in items]


s = []
s += [Spacer(1, 60 * mm), Paragraph("SentryScan", T),
      Paragraph("Autonomous Multi-Agent Cyber Security Platform<br/>Project Status, Architecture, Roadmap (v2.1, Nov 2026)",
                ParagraphStyle("sub", parent=B, alignment=1, fontSize=13)), PageBreak()]

s += [Paragraph("1. Executive summary", H1),
      Paragraph("SentryScan senses fleet telemetry, verifies it against poisoning, lets specialised agents negotiate "
                "(Contract-Net Protocol) who handles each case, deliberates with a BDI model, and contains threats through a "
                "remediation actuator. All inter-agent messages are Ed25519-signed. Every event is recorded in a JSONL "
                "audit stream and a SQLite store that feeds a web console.", B),
      Paragraph("The platform ships as two products plus a demo rig: the Executive Portal (<b>/</b>), the Master Cyber "
                "Console (<b>/master</b>) and the Demo Control Center (<b>/control</b>).", B),
      Paragraph("2. Architecture", H1),
      Paragraph("Data path: Fleet Sensors → Integrity Gate → Supervisor Graph (LangGraph + CNP auction) → VIGIL Collective "
                "(Scout, Triage, BDI Analyst) → Containment Actuator. Side paths: Zero-Trust Gate, Knowledge Enricher "
                "(ontology + NVD), LLM factory, Run Store, Dashboard Gateway (FastAPI + WebSocket), React console.", B),
      tbl([["Component", "Module", "Role"],
           ["Fleet Sensors", "simulation/fleet.py", "Simulated workstation and network telemetry"],
           ["Integrity Gate", "integrity/checker.py", "Detects poisoned or malformed telemetry"],
           ["Supervisor Graph", "graphs/supervisor.py", "State machine and Contract-Net auction"],
           ["BDI Analyst", "agents/analyst.py, bdi/", "Beliefs, desires, intentions, reconsideration"],
           ["Remediator", "agents/remediator.py", "Host isolation / quarantine actions"],
           ["Zero-Trust Gate", "security/gate.py", "Signature, nonce, replay, recipient checks"],
           ["Knowledge Enricher", "knowledge/enricher.py", "Ontology and CVE enrichment"],
           ["Run Store", "storage/store.py", "SQLite WAL relational store"],
           ["Recorder", "observability/recorder.py", "Gap-free JSONL event stream"],
           ["Gateway", "dashboard_gateway/server.py", "REST + WebSocket for the console"]],
          [38 * mm, 55 * mm, 80 * mm]),
      PageBreak()]

s += [Paragraph("3. What has been built", H1),
      Paragraph("Agents and reasoning", H2)] + bullets([
          "Scout, Triage, Analyst, Remediator and Reflex agents.",
          "BDI deliberation (beliefs, desires, intentions) with reconsideration tests.",
          "Weighted optimizer with formula, engine, brute-force and edge-case tests."]) + [
      Paragraph("Coordination and security", H2)] + bullets([
          "Contract-Net negotiation protocol with proposal roles and scoring.",
          "Ed25519 identity, canonical serialisation, registry, nonce cache.",
          "Rejection of forged, tampered, unknown, wrong-recipient, stale and replayed messages."]) + [
      Paragraph("Persistence and delivery", H2)] + bullets([
          "Dual-sink persistence: JSONL authoritative stream and SQLite tables "
          "(events, telemetry, messages, findings, bdi_deliberations, pending_quarantines, llm_calls).",
          "Loopback WebSocket gateway with resync by sequence; prebuilt dashboard bundle; Rich CLI fallback.",
          "One-command demo, replay and parity tests, human-traffic and poisoning simulators, ground-truth evaluator.",
          "Concurrency layer: queue manager, daemon, metrics and stats.",
          "Socket and in-process transports with framing."]) + [
      Paragraph("4. Run modes and log locations", H1),
      tbl([["Mode", "Command", "Output directory"],
           ["Continuous live SOC", "python main.py --live", "data/live/run-live.jsonl + .db"],
           ["Capstone demo", "python main.py --demo", "data/runs/capstone_demo/run-capstone-0042.*"],
           ["Human traffic test", "python main.py --test-human", "data/runs/human_test/run-human-test-0042.*"],
           ["Evaluation harness", "python main.py --eval", "data/runs/eval/run-eval-s{seed}-c{cycles}.*"]],
          [38 * mm, 55 * mm, 80 * mm]),
      Spacer(1, 4 * mm),
      Paragraph("Each event records event_id/seq, timestamp_utc, component, event_type "
                "(RECORD_RECEIVED, RECORD_REJECTED, MESSAGE_SENT, FINDING_CREATED, STATE_TRANSITION, PARAMS_UPDATE) and details.", B),
      PageBreak()]

s += [Paragraph("5. Recent change history", H1),
      tbl([["Commit", "Summary"],
           ["721dfdd", "Demo Control Center, POLARIS compliance rebuild, SQLite concurrency optimisation, README"],
           ["a5267d0", "CI fixes (lint, test deps, secret false-positives), dual-product README"],
           ["d9b8b37", "v2.0: VIGIL SOC, SENTRA Data Discovery, POLARIS Compliance"],
           ["7d0aedb", "Merge milestone 5.2 capstone and dashboard"],
           ["92dc6b6 – f113be8", "5.2: SQLite/JSONL persistence, WebSocket gateway, Rich dashboard, bundle, one-command demo"],
           ["32f34ef", "Merge milestone 5.1 message authentication"]],
          [38 * mm, 135 * mm]),
      Paragraph("6. Quality evidence", H1)] + bullets([
          "About 85 source modules and about 50 test files (counted from the repository listing).",
          "Integration tests: multi-agent coordination, BDI reconsideration, knowledge enrichment, capstone parity and replay.",
          "Unit tests span security gate, signing, identity, store, transport, supervisor graph, dashboard gateway."]) + [
      Paragraph("7. Remaining work", H1),
      tbl([["Item", "Detail", "Priority"],
           ["Real sensor ingestion", "Agent, syslog or EDR adapters instead of simulator", "High"],
           ["Live containment", "Actuators are dry-run; add approval flow and rollback", "High"],
           ["Console authN/authZ", "Users, roles, operator audit, agent key rotation", "High"],
           ["Packaging", "Docker/compose, config management, retention, metrics export", "Medium"],
           ["Live NVD cache", "Scheduled refresh and offline fallback", "Medium"]],
          [45 * mm, 100 * mm, 28 * mm]),
      PageBreak(),
      Paragraph("8. Refinement backlog", H1),
      tbl([["Area", "Issue", "Action"],
           ["Large modules", "store.py ~41 KB, server.py ~49 KB", "Split by concern (queries, writers, routes)"],
           ["Evaluation", "Limited scenarios", "Per-attack precision/recall report"],
           ["LLM layer", "Failure and cost handling", "Timeouts, retries, spend from llm_calls, prompt regression tests"],
           ["UI", "Polish gaps", "Accessibility, empty/error states, WebSocket load tests"],
           ["Docs", "Scattered", "Single architecture and operations guide"]],
          [32 * mm, 55 * mm, 86 * mm]),
      Paragraph("9. Roadmap (proposed)", H1)] + bullets([
          "<b>Phase 1 Harden:</b> split modules, console auth, CI quality gates.",
          "<b>Phase 2 Connect:</b> real sensor adapters, live NVD cache.",
          "<b>Phase 3 Act:</b> approved live containment with rollback.",
          "<b>Phase 4 Ship:</b> containers, operations docs, benchmark report."]) + [
      Spacer(1, 6 * mm),
      Paragraph("<i>Note: counts and maturity estimates derive from file listings, git log and the architecture diagram; "
                "no test run was executed for this report. Roadmap items are proposals.</i>", B)]

SimpleDocTemplate("SentryScan_Report.pdf", pagesize=A4, leftMargin=18 * mm, rightMargin=18 * mm,
                  topMargin=18 * mm, bottomMargin=18 * mm, title="SentryScan Project Report").build(s)
