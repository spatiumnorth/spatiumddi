"""The SVCB / HTTPS translation block is shared, byte for byte, with the agent.

The agent image cannot import ``app``, so ``agent/dns/spatium_dns_agent/
drivers/technitium.py`` carries its own copy of the block in
``app/services/technitium/rdata.py``. If the two drift, the agent and the
agentless driver send — and drift compares — different forms of the same
record, which is the #1513 churn again. Pin them equal, comments and blank
lines aside.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

_BACKEND = Path(__file__).parents[1] / "app/services/technitium/rdata.py"
_AGENT = Path(__file__).parents[2] / "agent/dns/spatium_dns_agent/drivers/technitium.py"
_START = "# ── SVCB / HTTPS (RFC 9460)"
_END = "# ── end of the block shared with the agent"


def _block(path: Path) -> list[str]:
    text = path.read_text()
    assert _START in text and _END in text, f"{path} lost its shared-block markers"
    body = text[text.index(_START) : text.index(_END)]
    # Comments and blank lines aside: black spaces the end of the block by
    # what follows it, which differs between the two files.
    return [ln for ln in body.splitlines() if ln.strip() and not ln.lstrip().startswith("#")]


@pytest.mark.skipif(not _AGENT.exists(), reason="agent package not in this checkout")
def test_svcb_block_matches_the_agent_copy() -> None:
    assert _block(_BACKEND) == _block(_AGENT)


def _frozenset_literal(path: Path, name: str) -> frozenset[str]:
    for node in ast.parse(path.read_text()).body:
        if (
            isinstance(node, ast.Assign)
            and any(isinstance(t, ast.Name) and t.id == name for t in node.targets)
            and isinstance(node.value, ast.Call)
        ):
            return frozenset(ast.literal_eval(node.value.args[0]))
    raise AssertionError(f"{path} lost {name}")


@pytest.mark.skipif(not _AGENT.exists(), reason="agent package not in this checkout")
def test_idempotent_noop_messages_match_the_agent_copy() -> None:
    """#1770 — the agent and the agentless driver must agree on which
    Technitium errors mean "already in that state"; a drift makes one of
    them report applied for an op the other reports failed."""
    backend = _frozenset_literal(_BACKEND, "_NOOP_MESSAGES")
    agent = _frozenset_literal(_AGENT, "_RECORD_NOOP_MESSAGES")
    assert backend == agent
    assert not any("use overwrite option" in m for m in backend)
    assert '"zone already exists:"' in _BACKEND.read_text()
    assert '"zone already exists:"' in _AGENT.read_text()
