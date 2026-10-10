"""The SVCB / HTTPS translation block is shared, byte for byte, with the agent.

The agent image cannot import ``app``, so ``agent/dns/spatium_dns_agent/
drivers/technitium.py`` carries its own copy of the block in
``app/services/technitium/rdata.py``. If the two drift, the agent and the
agentless driver send — and drift compares — different forms of the same
record, which is the #1513 churn again. Pin them equal, comments and blank
lines aside.
"""

from __future__ import annotations

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
