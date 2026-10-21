# Contract-Net Negotiation Turn-by-Turn Timeline

**Task ID:** `task-fleet-allocation`  
**Status:** `CONSENSUS_REACHED`  
**Rounds:** 2

| Step | Sender | Receiver | Performative | Summary | Nonce |
|---|---|---|---|---|---|
| 1 | `supervisor-agent` | `scout-agent` | `CFP` | Round 1: Constraints {'max_cost': 10.5, 'max_time': 250.0} | `30877432d1026706` |
| 2 | `supervisor-agent` | `triage-agent` | `CFP` | Round 1: Constraints {'max_cost': 10.5, 'max_time': 250.0} | `d7e805da846a32c3` |
| 3 | `scout-agent` | `supervisor-agent` | `PROPOSE` | Batches ['batch-03'], Cost 11.0, Cov 0.2 | `bb81e3c29b621792` |
| 4 | `triage-agent` | `supervisor-agent` | `PROPOSE` | Batches ['batch-02'], Cost 13.0, Cov 0.54 | `73c8eb5bb682575e` |
| 5 | `supervisor-agent` | `scout-agent` | `COUNTERPROPOSE` | Round 2: Constraints {'max_cost': 12.075, 'max_time': 287.5} | `c87a171ac826a6fc` |
| 6 | `supervisor-agent` | `triage-agent` | `COUNTERPROPOSE` | Round 2: Constraints {'max_cost': 12.075, 'max_time': 287.5} | `e48478dcb74f2134` |
| 7 | `scout-agent` | `supervisor-agent` | `PROPOSE` | Batches ['batch-03'], Cost 11.0, Cov 0.2 | `5d2cce8038a39d5e` |
| 8 | `triage-agent` | `supervisor-agent` | `PROPOSE` | Batches ['batch-02'], Cost 13.0, Cov 0.54 | `0853964b50af03b9` |
| 9 | `supervisor-agent` | `scout-agent` | `ACCEPT` | AWARDED ['batch-03'], Score -0.1256 | `71722f244f58d669` |
| 10 | `supervisor-agent` | `triage-agent` | `REJECT` | Alternative proposal yielded higher normalized utility score | `cbee3772a0770217` |
| 11 | `scout-agent` | `supervisor-agent` | `CONFIRM` | AWARD_CONFIRMED | `21a278f64f7fd633` |
