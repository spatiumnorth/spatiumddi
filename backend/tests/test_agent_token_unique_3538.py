"""#3538 — two agent tokens minted in the same second must differ.

Staleness is judged by comparing the stored ``agent_jwt_hash`` with the
presented token's hash. ``exp`` has whole-second resolution and the claims
are otherwise the same for one server, so a replacement token minted in the
same second as the one it replaces was byte-identical to it: the displaced
agent's token still passed (the flaky #2219 duplicate-pair test).
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from app.services.dhcp import agent_token as dhcp_tok
from app.services.dns import agent_token as dns_tok
from app.services.looking_glass import agent_token as lg_tok


class _Frozen(datetime):
    @classmethod
    def now(cls, tz=None):  # type: ignore[no-untyped-def]
        return datetime(2026, 11, 5, 12, 0, 0, 123456, tzinfo=UTC)


@pytest.mark.parametrize("mod", [dns_tok, dhcp_tok, lg_tok])
def test_same_second_tokens_differ(mod, monkeypatch: pytest.MonkeyPatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setattr(mod, "datetime", _Frozen)
    t1, _ = mod.mint_agent_token("srv", "agent", "fp")
    t2, _ = mod.mint_agent_token("srv", "agent", "fp")
    assert t1 != t2
    assert mod.hash_token(t1) != mod.hash_token(t2)
    mod.verify_agent_token(t1)
    mod.verify_agent_token(t2)
