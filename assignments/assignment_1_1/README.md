# Assignment 1.1 — PEAS & Environment Modelling

**Course:** 21CSE525T — Agent Technology  
**Student:** R Ganesh [RA2212704010031]  
**Deliverable Status:** Completed & Verified  
**Git Tag:** `assignment-1.1`  

---

## 1. Executive Summary

Assignment 1.1 establishes the foundational theoretical, behavioral, and architectural specifications for **SentryScan**—an authorized autonomous vulnerability scanner agent simulation designed for synthetic telemetry analysis.

Key deliverables include:
- **Agent Persona & Problem Formulation:** Highlighting defensive posture assessment, telemetry alert fatigue, and strict simulation boundaries.
- **PEAS Formalization:** Performance measures (detection accuracy, integrity defense, latency), Environment (simulated fleet, isolated ground truth), Actuators (findings, event recorder, envelopes), and Sensors (ingestion, integrity parser, socket framing).
- **Environment Taxonomy (Russell & Norvig):** Partially Observable, Stochastic, Sequential, Dynamic, Discrete, Multi-Agent, and Known.
- **Agent Architecture vs. OOP:** Deep comparative analysis citing control autonomy, cognitive mental states (BDI), situatedness, and speech-act semantics, grounded in the Unit-1 agent taxonomy.
- **Initial Architecture & Environment Diagrams:** Vector SVG diagrams illustrating data flow, trust boundaries, and persistence.
- **Future Roadmap:** Seamless evolutionary path connecting the reflex agent to concurrency (2.1), sockets (2.2), LangGraph coordination (3.1), utility optimization (3.2), and BDI deliberation (4.1).

---

## 2. Deliverables & Artifacts

All required artifacts reside within this folder:
- **Design Specification PDF:** [`deliverables/SentryScan_Design_Specification.pdf`](deliverables/SentryScan_Design_Specification.pdf)
- **Design Specification Markdown:** [`deliverables/SentryScan_Design_Specification.md`](deliverables/SentryScan_Design_Specification.md)
- **Standalone HTML Report:** [`deliverables/SentryScan_Design_Specification.html`](deliverables/SentryScan_Design_Specification.html)
- **Architectural Diagrams (Vector SVG):**
  - [`deliverables/diagrams/architecture.svg`](deliverables/diagrams/architecture.svg)
  - [`deliverables/diagrams/environment_model.svg`](deliverables/diagrams/environment_model.svg)
- **Rubric Mapping:** [`rubric_map.md`](rubric_map.md)
- **Verification Checklist:** [`evidence/checklist.md`](evidence/checklist.md)

---

## 3. Reproduction & Packaging Instructions

To re-export the PDF deliverable or generate the submission ZIP from the immutable Git tag:

```bash
# Re-generate specification HTML and PDF
python scripts/export_specification_pdf.py

# Package submission archive from immutable tag
python scripts/package_assignment.py assignment-1.1
```
