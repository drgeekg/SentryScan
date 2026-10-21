# Ten-Candidate Execution Plan Optimization Table

**Active Constraints:** Cost $\le 50.0$, Time $\le 400.0$ ms  
**Weights:** $w_{sev}=0.35$, $w_{hosts}=0.25$, $w_{cost}=0.15$, $w_{time}=0.15$, $w_{risk}=0.1$

| Plan ID | Proposer | $C_{sev}$ | $C_{hosts}$ | Cost | Time (ms) | Risk | Feasible? | Score $U(o)$ | Status / Decision |
|---|---|---|---|---|---|---|:---:|:---:|---|
| `plan-01-minimal` | `scout-agent` | 0.30 | 0.40 | 12.0 | 60.0 | 0.20 | ✅ Yes | `+0.1580` | Suboptimal |
| `plan-02-breadth` | `scout-agent` | 0.65 | 0.85 | 28.0 | 150.0 | 0.12 | ✅ Yes | `+0.3635` | Suboptimal |
| `plan-03-risk-heavy` | `triage-agent` | 0.90 | 0.60 | 32.0 | 180.0 | 0.06 | ✅ Yes | `+0.3840` | Suboptimal |
| `plan-04-balanced-opt` | `triage-agent` | 0.92 | 0.88 | 45.0 | 220.0 | 0.05 | ✅ Yes | `+0.4365` | WINNER (argmax o*) |
| `plan-05-fast-triage` | `triage-agent` | 0.75 | 0.35 | 18.0 | 80.0 | 0.10 | ✅ Yes | `+0.3010` | Suboptimal |
| `plan-06-infeasible-cost` | `scout-agent` | 0.98 | 0.95 | 78.0 | 310.0 | 0.04 | ❌ No | `-inf` | REJECTED: COST_EXCEEDED (78.0 > 50.0) |
| `plan-07-infeasible-time` | `triage-agent` | 0.80 | 0.70 | 40.0 | 450.0 | 0.08 | ❌ No | `-inf` | REJECTED: TIME_EXCEEDED (450.0 > 400.0) |
| `plan-08-empty-batch` | `scout-agent` | 0.00 | 0.00 | 0.0 | 0.0 | 0.50 | ❌ No | `-inf` | REJECTED: EMPTY_BATCH_LIST |
| `plan-09-moderate-breadth` | `scout-agent` | 0.50 | 0.70 | 22.0 | 110.0 | 0.15 | ✅ Yes | `+0.2855` | Suboptimal |
| `plan-10-high-risk-lean` | `triage-agent` | 0.82 | 0.50 | 24.0 | 130.0 | 0.07 | ✅ Yes | `+0.3495` | Suboptimal |
