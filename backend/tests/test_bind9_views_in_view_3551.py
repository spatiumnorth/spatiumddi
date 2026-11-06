"""The control-plane BIND9 render shares identical view copies (#3551).

The agent renderer loads a zone whose copy is identical across views once and
references it from later views with ``in-view``. The control-plane preview
renders the same named.conf shape, so it does the same; without it the
preview also gave two views the same writable zone file, which named refuses.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from types import SimpleNamespace

from app.drivers.dns.base import ConfigBundle, RecordData, ServerOptions, ViewData, ZoneData
from app.drivers.dns.bind9 import BIND9Driver

_WWW = RecordData(name="www", record_type="A", value="192.0.2.10", ttl=300)


def _z(view: str, records: tuple[RecordData, ...] = (_WWW,), **extra: object) -> ZoneData:
    return ZoneData(
        name="example.com.",
        zone_type=str(extra.pop("zone_type", "primary")),
        kind="forward",
        ttl=3600,
        refresh=86400,
        retry=7200,
        expire=3600000,
        minimum=3600,
        primary_ns="ns1.example.com.",
        admin_email="hostmaster.example.com.",
        serial=2026110501,
        records=records,
        view_name=view,
        **extra,  # type: ignore[arg-type]
    )


def _render(*zones: ZoneData) -> str:
    b = ConfigBundle(
        server_id=str(uuid.uuid4()),
        server_name="ns1",
        driver="bind9",
        roles=("authoritative",),
        options=ServerOptions(),
        acls=(),
        views=(
            ViewData(
                name="restricted",
                match_clients=("192.0.2.0/24",),
                match_destinations=(),
                recursion=True,
                order=0,
            ),
            ViewData(
                name="default",
                match_clients=("any",),
                match_destinations=(),
                recursion=True,
                order=1,
            ),
        ),
        zones=zones,
        tsig_keys=(),
        blocklists=(),
        generated_at=datetime(2026, 11, 5, 12, 0, tzinfo=UTC),
    )
    return BIND9Driver().render_server_config(
        SimpleNamespace(id=b.server_id, name=b.server_name), b.options, bundle=b
    )


def _default_view(out: str) -> str:
    return out.split('view "default" {', 1)[1]


def test_an_identical_copy_is_referenced_in_view() -> None:
    out = _render(_z("restricted"), _z("default"))
    assert out.index('view "restricted"') < out.index('view "default"')
    assert out.count("type master;") == 1
    assert 'zone "example.com." { in-view "restricted"; };' in _default_view(out)


def test_a_view_specific_record_keeps_its_own_copy() -> None:
    other = RecordData(name="www", record_type="A", value="198.51.100.10", ttl=300)
    out = _render(_z("restricted"), _z("default", (other,)))
    assert "in-view" not in out
    assert out.count("type master;") == 2


def test_differing_zone_options_keep_their_own_copy() -> None:
    out = _render(_z("restricted"), _z("default", allow_transfer=("192.0.2.53",)))
    assert "in-view" not in out


def test_forward_zones_are_never_referenced_in_view() -> None:
    out = _render(
        _z("restricted", (), zone_type="forward", forwarders=("192.0.2.1",)),
        _z("default", (), zone_type="forward", forwarders=("192.0.2.1",)),
    )
    assert "in-view" not in out
    assert out.count("type forward;") == 2
