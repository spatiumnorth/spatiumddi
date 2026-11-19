"""The CAA helper is shared, byte for byte, with the DNS agent (#1760).

The agent image cannot import ``app``, so ``agent/dns/spatium_dns_agent/
drivers/_caa.py`` is a copy of ``app/drivers/dns/_caa.py``; both module
docstrings say to change them together. If they drift, the agent and the
control plane send, and drift compares, different strings for one record —
which is how #1694 fixed the agent and left the agentless driver broken.
"""

from __future__ import annotations

from pathlib import Path

import pytest

_BACKEND = Path(__file__).parents[1] / "app/drivers/dns/_caa.py"
_AGENT = Path(__file__).parents[2] / "agent/dns/spatium_dns_agent/drivers/_caa.py"


@pytest.mark.skipif(not _AGENT.exists(), reason="agent package not in this checkout")
def test_caa_helper_matches_the_agent_copy() -> None:
    assert _BACKEND.read_bytes() == _AGENT.read_bytes()
