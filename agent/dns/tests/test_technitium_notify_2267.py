"""Technitium zone NOTIFY (#2267): the group's / zone's ``notify`` +
``also_notify`` reach the daemon as ``notify`` + ``notifyNameServers``, asserted
on the ``zones/options/set`` call actually sent."""

from __future__ import annotations

from typing import Any

import pytest

from spatium_dns_agent.drivers.technitium import TechnitiumDriver, _zone_options_payload


def _bundle(**opts: Any) -> dict[str, Any]:
    return {"options": opts}


def _payload(ztype: str = "Primary", zone: dict | None = None, **opts: Any) -> dict[str, Any]:
    return _zone_options_payload(ztype, _bundle(**opts), zone)


def _notify(p: dict[str, Any]) -> tuple[Any, Any]:
    return p.get("notify"), p.get("notifyNameServers")


def test_notify_no_is_none_and_clears_targets() -> None:
    p = _payload(notify_enabled="no", also_notify=["10.0.0.1"])
    assert _notify(p) == ("None", [])


def test_notify_yes_without_targets_is_the_ns_set() -> None:
    assert _notify(_payload(notify_enabled="yes", also_notify=[])) == ("ZoneNameServers", [])
    # An absent setting is BIND's default, ``yes``.
    assert _notify(_payload()) == ("ZoneNameServers", [])


def test_notify_yes_with_targets_is_both() -> None:
    p = _payload(notify_enabled="yes", also_notify=["10.0.0.1", "2001:db8::1"])
    assert _notify(p) == ("BothZoneAndSpecifiedNameServers", ["10.0.0.1", "2001:db8::1"])


def test_notify_explicit_is_only_the_targets() -> None:
    p = _payload(notify_enabled="explicit", also_notify=["10.0.0.1"])
    assert _notify(p) == ("SpecifiedNameServers", ["10.0.0.1"])
    # BIND notifies nobody for ``explicit`` with no also-notify list.
    assert _notify(_payload(notify_enabled="explicit")) == ("None", [])


def test_primary_only_notifies_from_a_primary_not_a_secondary() -> None:
    assert _notify(_payload("Primary", notify_enabled="primary-only"))[0] == "ZoneNameServers"
    assert _notify(_payload("Secondary", notify_enabled="master-only"))[0] == "None"


def test_zone_value_overrides_group() -> None:
    p = _payload(
        zone={"notify_enabled": "no", "also_notify": None},
        notify_enabled="yes",
        also_notify=["10.0.0.1"],
    )
    assert _notify(p) == ("None", [])
    p = _payload(
        zone={"notify_enabled": None, "also_notify": ["10.9.9.9"]},
        notify_enabled="yes",
        also_notify=["10.0.0.1"],
    )
    assert _notify(p) == ("BothZoneAndSpecifiedNameServers", ["10.9.9.9"])
    # A zone's empty list inherits, as the BIND9 agent renders nothing for it.
    p = _payload(zone={"also_notify": []}, also_notify=["10.0.0.1"])
    assert _notify(p)[1] == ["10.0.0.1"]


def test_only_primary_and_secondary_zones_carry_notify() -> None:
    assert "notify" not in _payload("Forwarder", notify_enabled="no")
    assert "notify" not in _payload("Stub", notify_enabled="no")
    assert _notify(_payload("Secondary", notify_enabled="no"))[0] == "None"


def test_a_non_address_target_is_skipped_and_reported() -> None:
    p = _payload(notify_enabled="yes", also_notify=["10.0.0.1", "10.0.0.2 port 53"])
    assert _notify(p) == ("BothZoneAndSpecifiedNameServers", ["10.0.0.1"])
    assert [u["kind"] for u in p["_unapplied"]] == ["also_notify"]


def test_the_options_call_sent_carries_the_notify_fields() -> None:
    drv = TechnitiumDriver.__new__(TechnitiumDriver)
    drv._unapplied_acl = None
    sent: list[dict[str, Any]] = []

    class _Resp:
        def json(self) -> dict[str, Any]:
            return {"status": "ok"}

    def _call(token: str, method: str, path: str, params: dict[str, Any]) -> _Resp:
        sent.append({"path": path, **params})
        return _Resp()

    drv._call = _call  # type: ignore[method-assign]
    drv._note_apply_failure = pytest.fail  # type: ignore[method-assign]
    p = _payload(notify_enabled="explicit", also_notify=["10.0.0.1", "10.0.0.2"])
    assert drv._apply_zone_options("tok", "example.test", p) is True
    assert sent[0]["path"] == "zones/options/set"
    assert sent[0]["notify"] == "SpecifiedNameServers"
    assert sent[0]["notifyNameServers"] == "10.0.0.1,10.0.0.2"
    assert "_unapplied" not in sent[0]
