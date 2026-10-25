# SentryScan — "Ledger" Design System (`DESIGN.md`)

## Design Philosophy
Built for **Operate Mode**: high-density security operations where scanability, crisp hierarchy, keyboard accessibility, and unambiguous status signaling outrank ornamental effects. Supports instant **Light / Dark theme switching** persisted in `localStorage`.

## Color Tokens

| Semantic Token | Light Theme (`[data-theme="light"]`) | Dark Theme (`[data-theme="dark"]`) | Purpose |
| :--- | :--- | :--- | :--- |
| `--bg-canvas` | `#F3F5F8` | `#0B0F17` | App background canvas |
| `--bg-surface` | `#FFFFFF` | `#111827` | Primary cards, tables, panels |
| `--bg-elevated` | `#F8FAFC` | `#1E293B` | Hover rows, secondary containers, drawers |
| `--bg-sidebar` | `#0E1626` | `#070B12` | Left navigation rail |
| `--border-subtle` | `#E2E8F0` | `#1F2937` | Card & table hairlines |
| `--border-strong` | `#CBD5E1` | `#334155` | Active input / focus borders |
| `--text-primary` | `#0F172A` | `#F1F5F9` | Headings, primary values |
| `--text-secondary` | `#475569` | `#94A3B8` | Body copy, table cells |
| `--text-muted` | `#64748B` | `#64748B` | Captions, timestamps, metadata |
| `--accent-primary` | `#4F46E5` | `#6366F1` | Primary interactive accent, active rail |
| `--sev-critical` | `#DC2626` | `#F87171` | Critical severity (paired with icon + text) |
| `--sev-high` | `#EA580C` | `#FB923C` | High severity |
| `--sev-medium` | `#D97706` | `#FBBF24` | Medium severity |
| `--sev-low` | `#2563EB` | `#60A5FA` | Low / informational severity |
| `--status-pass` | `#059669` | `#34D399` | Passing control / contained status |

## Typography & Hierarchy
- **UI Sans**: `'Inter'`, `'Segoe UI'`, `system-ui`, `-apple-system`, `sans-serif`
- **Technical Mono**: `'JetBrains Mono'`, `'Cascadia Code'`, `Consolas`, `monospace`
- **Scale Floor**: Minimum `12px` (`0.75rem`) for badges and metadata; `13px–14px` for table cells and body copy; `18px–24px` for section headers and KPI numerals.

## Core Layout & Components
- **Left Navigation Sidebar (`240px` fixed)**: Module-grouped navigation (`Overview`, `PROACT SOC`, `RADAR Discovery`, `Pulse Compliance`, `Assets & Fleet`, `Simulation Lab`, `Live Agent Ops`), run selector, and connection heartbeat.
- **Top Utility Bar (`56px`)**: Breadcrumb, active Industry Profile & Framework badge, `SIMULATED` provenance indicator, Copilot & Reports drawer triggers, and **Light / Dark Theme Toggle**.
- **KPI Ring Gauge Cards**: SVG circular progress gauges with status pills (`GOOD`, `FAIR`, `AT RISK`, `CRITICAL`), contextual sub-metrics, and direct drill-down CTAs.
- **Cross-Module Entity Chips**: Clickable pills for `Host ID`, `Incident ID`, `Control ID`, and `Source ID` enabling zero-dead-end navigation (`Alert -> Incident -> Asset -> RADAR Finding -> Pulse Control -> Evidence -> Remediation`).
