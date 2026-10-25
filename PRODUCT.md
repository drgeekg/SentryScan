# SentryScan — Product Specification

## Mission
SentryScan is an industry-agnostic **Agentic SOC (PROACT) + Sensitive Data Discovery (RADAR) + Continuous Compliance (Pulse)** platform. It ingests telemetry from heterogeneous enterprise assets (endpoints, servers, network appliances, cloud accounts, and SaaS tenants), coordinates multi-agent investigation and containment, discovers sensitive data exposures, and continuously evaluates security controls with linked provenance evidence.

## Core Modules
1. **Executive Overview**: Unified organizational posture, security & compliance index gauges, active incident queue, sensitive data exposure summary, and failing control categories.
2. **PROACT (Agentic SOC)**: Alert queue with multi-axis filters, correlated incident workspace, cryptographic agent negotiation (Scout vs. Triage), 3-tier BDI Analyst hierarchy (L1 Triage, L2 Incident, L3 Containment), and human-in-the-loop quarantine approval gate.
3. **RADAR (Data Discovery & Classification)**: Configurable regex/keyword policy engine across PII, Health, Financial, Intellectual Property, Credentials, and custom organizational data categories. All discovery in POC mode is clearly badged `SIMULATED`.
4. **Pulse (Continuous Compliance & Evidence)**: Configurable industry profile & framework registry (`Baseline-8`, illustrative `ISO/IEC 27001`, `NIST CSF 2.0`), automated control evaluation from real PROACT & RADAR signals, evidence freshness tracking, and remediation workflow management.
5. **Asset Inventory & Simulation Engine**: 11 typed enterprise asset classes (`windows_workstation`, `linux_workstation`, `linux_server`, `cisco_router`, `firewall`, `aws_account`, `azure_tenant`, `m365_tenant`, `database_server`, `iot_device`, `saas_app`) with configurable per-type counts (`--fleet`) and seeded random fill.
6. **Live Agent Operations**: Real-time topology visualization, message timeline, BDI belief inspector, and historical event replay scrubber.
