"""Copilot Watch (issue #4405) — the service layer.

An opt-in background agent that reviews what the deterministic detectors
found (alerts, conformity, server health, agent failures) and files
findings. It observes and advises: no module here stages or applies a
change, and none of the tools it may call can.

* ``principal`` — the non-login identity every run acts as.
* ``providers`` — which LLM providers a run may use (on-prem by default).
* ``tools`` — the read-only tool allowlist.
* ``evidence`` — the deterministic evidence pack and reference checks.
* ``findings`` — the output schema, validation, dedup and lifecycle.
* ``budget`` — the daily token and cost budget.
* ``runner`` — the tick: triggers, guards and one run.
"""
