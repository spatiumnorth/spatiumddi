"""The BIND address-match translation is shared, byte for byte, with the agent (#1765).

The agent image cannot import ``app``, so ``agent/dns/spatium_dns_agent/
drivers/technitium.py`` carries its own copy of the block in
``app/services/dns/technitium_options.py``. The API refuses what the block
cannot translate and the agent applies what it can, so if the two drift an
accepted value is applied differently from how it was validated.
"""

from __future__ import annotations

from pathlib import Path

import pytest

_BACKEND = Path(__file__).parents[1] / "app/services/dns/technitium_options.py"
_AGENT = Path(__file__).parents[2] / "agent/dns/spatium_dns_agent/drivers/technitium.py"
_START = "# ── BIND address-match translation"
_END = "# ── end of the block shared with the agent"


def _block(path: Path) -> list[str]:
    text = path.read_text()
    assert _START in text and _END in text, f"{path} lost its shared-block markers"
    start = text.index(_START)
    body = text[start : text.index(_END, start)]
    return [ln for ln in body.splitlines() if ln.strip() and not ln.lstrip().startswith("#")]


@pytest.mark.skipif(not _AGENT.exists(), reason="agent package not in this checkout")
def test_the_translation_block_matches_the_agent_copy() -> None:
    assert _block(_BACKEND) == _block(_AGENT)
