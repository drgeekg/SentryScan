# Assignment 3.1 Acceptance Checklist

- [x] LangGraph dependency pinned in `requirements.txt` (`langgraph>=0.2.0,<2.0.0`) and `pyproject.toml`.
- [x] Typed graph state defined in `src/sentryscan/graphs/state.py` (`SupervisorState`) with `operator.add` reducers for `messages`, `findings`, and `errors`.
- [x] Provider-neutral LLM layer implemented in `src/sentryscan/llm/` with `LLMRequest`, `LLMResponse`, and `LLMProvider` protocol.
- [x] `DeterministicLLMProvider` implemented providing reproducible, zero-network template rationales.
- [x] `FakeLLMProvider` implemented for testing and failure simulation.
- [x] Proposal contract implemented in `src/sentryscan/contracts/proposal.py` (`Proposal` model).
- [x] `ScoutAgent` implemented prioritizing broad fleet and subnet host coverage.
- [x] `TriageAgent` implemented prioritizing high-severity, critical security exposures.
- [x] `score_bid()` implemented in `src/sentryscan/negotiation/scoring.py` with hard constraint filtering ($-\infty$) and normalized multi-attribute objective scoring.
- [x] Multi-turn Contract-Net negotiation protocol implemented (`CFP` $\to$ `PROPOSE` $\to$ `COUNTERPROPOSE` $\to$ `ACCEPT` / `REJECT` $\to$ `CONFIRM`).
- [x] Turn-by-turn negotiation timeline generated and committed in [`negotiation_timeline.md`](negotiation_timeline.md).
- [x] LangGraph supervisor workflow compiled with dynamic runtime worker fan-out via `Send("scanner_worker", ...)`.
- [x] Scanner workers run deterministic `RuleEngine` across awarded batches and aggregate findings.
- [x] Bounded loop termination verified (terminating safely in `UNRESOLVED` when constraints cannot be satisfied, with 0 infinite loops).
- [x] Determinism contract verified (identical traces and decision outcomes across runs with LLM off).
- [x] Advisory LLM verified non-authoritative (does not change mathematical utility or winner selection).
- [x] All 70 pytest tests pass cleanly with 0 failures and 0 warnings.
- [x] Ruff lint checks pass cleanly with 0 errors across entire repository.
