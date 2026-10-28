"""#2950 — the core.dns / core.dhcp copy must match the register guards."""

from app.services.feature_modules import MODULES


def _desc(mid: str) -> str:
    return next(m for m in MODULES if m.id == mid).description


def test_core_descriptions_state_registration_is_refused_while_off() -> None:
    for mid in ("core.dns", "core.dhcp"):
        text = " ".join(_desc(mid).split())
        assert "deliberately unaffected" not in text
        assert "new agents cannot register" in text
        assert "already registered keep heartbeating and polling" in text
