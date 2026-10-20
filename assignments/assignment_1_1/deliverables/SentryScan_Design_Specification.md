# SentryScan: Agent Architecture & Environment Specification

**Course:** 21CSE525T — Agent Technology  
**Assignment:** 1.1 — PEAS & Environment Modelling  
**Student:** R Ganesh [RA2212704010031]  
**Repository:** https://github.com/drgeekg/SentryScan  
**Status:** Submitted  
**Git Tag:** `assignment-1.1`  

---

## 1. Persona & Problem Statement

### 1.1 Problem Statement
Modern enterprise infrastructure produces massive volumes of security telemetry—service banners, port states, TLS handshakes, and access logs across thousands of endpoints. Security operations centers (SOCs) face two chronic bottlenecks:
1. **Alert Fatigue & Noisy Prioritization:** Uncorrelated alerts overwhelm human operators; high-severity critical exposures get buried under thousands of low-impact notices.
2. **Operational Disruption of Live Probing:** Active vulnerability probing (e.g., intrusive scanning, fuzzing, packet flooding) risks taking down delicate operational technology (OT) or violating legal and organizational compliance boundaries.

There is an acute need for an **autonomous, non-intrusive security analysis agent** capable of ingesting streaming endpoint telemetry, validating data integrity, detecting high-risk exposures through deterministic reasoning, and deliberating over threat posture without active live scanning.

### 1.2 Agent Persona: SentryScan
**SentryScan** is an authorized, defensive security analyst agent designed to simulate intelligent vulnerability triage. 

* **Role:** Autonomous Defensive Telemetry Analyst.
* **Core Philosophy:** SentryScan operates strictly on *perceived telemetry* rather than active exploitation. It acts as an observant, rule-grounded, and deliberative defender.
* **Operational Scope:**
  - Ingests structured synthetic telemetry records representing network services and host metadata.
  - Distinguishes authentic telemetry from poisoned or corrupted records without access to ground-truth answer keys.
  - Applies explicit condition–action rules to identify confirmed exposures (e.g., deprecated protocols, default credentials, exposed administrative interfaces).
  - Prioritizes remediation based on explicit multi-attribute utility and updates internal mental states (BDI) as threat context evolves.

### 1.3 Safety Boundary & Ethical Simulation Mandate
To maintain strict ethical boundaries and academic reproducibility:
- **Synthetic Simulation Only:** SentryScan does **not** perform network-level packet craft, port scanning, credential stuffing, or exploit execution.
- **Documentation Address Space:** All host addresses strictly use IETF documentation ranges (RFC 5737: `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`; RFC 3849: `2001:db8::/32`). SentryScan never attempts socket connections to these addresses.
- **Untrusted Telemetry Guarantee:** All banners and external strings are treated as untrusted data inputs, precluding prompt-injection side channels or unvalidated execution.
