"""#1760: TXT compares by its character-strings on every pull path.

* The comparison key canonicalises TXT to presentation form, case kept, so a
  bare and a quoted spelling of one record key the same.
* The AXFR reader (BIND9, agent-managed Technitium, Windows Path A) keeps an
  explicit string split and every octet, so a DKIM key stored as two quoted
  strings is no longer permanent drift that Sync "repairs" by importing a
  merged duplicate.
* On a ``technitium_api`` server, a TXT written in the pre-#1760 broken form
  is the DB row served wrong: Sync does not import it, and its push carries
  the whole RRset so the replacement does not retire the record's siblings.
"""

from __future__ import annotations

import base64
import uuid
from types import SimpleNamespace
from typing import Any

import pytest

from app.drivers.dns._axfr import axfr_zone_records
from app.drivers.dns._txt import quote_txt
from app.drivers.dns.base import RecordChangeResult, RecordData
from app.models.dns import DNSRecord, DNSZone
from app.services.dns.pull_from_server import (
    _additive_import,
    _additive_push,
    _key,
    _normalize_value,
    _not_importable,
)
from app.services.technitium.rdata import rdata_to_value, record_params

_ZONE = "example.com."

# Stored TXT values the UI, the API and the importers can produce.
_VALUES = [
    "v=spf1 -all",
    '"v=spf1 -all"',
    # A DKIM key as providers print it: two quoted strings.
    '"v=DKIM1; k=rsa; p=AAA" "BBB"',
    # Escaped quote and backslash.
    '"say \\"hi\\" \\\\ back"',
    # \DDD: a UTF-8 é, then a lone octet that is not UTF-8.
    '"caf\\195\\169 \\233"',
    "Hello.",
    'a "quoted" word',
    # Over 255 octets, bare and as one quoted string.
    "x" * 300,
    '"' + "y" * 300 + '"',
    # Empty strings: alone, and between two others (DNS-SD).
    '""',
    '"svc=1" "" "k=v"',
]


def test_bare_and_quoted_txt_key_the_same() -> None:
    assert _normalize_value("TXT", "v=spf1 -all", _ZONE, relative_targets=True) == _normalize_value(
        "TXT", '"v=spf1 -all"', _ZONE, relative_targets=True
    )


def test_txt_case_is_significant() -> None:
    a = _key(RecordData(name="@", record_type="TXT", value='"AbC"'), _ZONE, relative_targets=True)
    b = _key(RecordData(name="@", record_type="TXT", value='"abc"'), _ZONE, relative_targets=True)
    assert a != b


def test_split_strings_are_not_merged() -> None:
    assert _normalize_value("TXT", '"a" "b"', _ZONE, relative_targets=True) != _normalize_value(
        "TXT", '"ab"', _ZONE, relative_targets=True
    )


@pytest.mark.parametrize("value", _VALUES)
def test_dnspython_presentation_form_canonicalises_to_the_stored_value(value: str) -> None:
    """dnspython prints non-ASCII as ``\\DDD`` where ``quote_txt`` prints the
    character; both parse to the same octets, so they key the same."""
    import dns.rdata

    rdata = dns.rdata.from_text("IN", "TXT", quote_txt(value))
    assert _normalize_value(
        "TXT", rdata.to_text(), _ZONE, relative_targets=True
    ) == _normalize_value("TXT", value, _ZONE, relative_targets=True)


async def test_bind9_axfr_reads_back_the_key_the_db_row_has(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Render each value as the BIND9 renderers do, let BIND's parser (here
    dnspython's) load it, transfer it, and compare: every record is in sync.
    Joining the strings on the AXFR side made the split ones permanent drift.
    """
    import dns.query
    import dns.zone

    lines = [
        "$ORIGIN example.com.",
        "$TTL 300",
        "@ SOA ns1 hostmaster 1 7200 3600 1209600 300",
        "@ NS ns1",
        "ns1 A 192.0.2.1",
    ]
    lines += [f"t{i} TXT {quote_txt(v)}" for i, v in enumerate(_VALUES)]
    served = dns.zone.from_text("\n".join(lines) + "\n", origin=_ZONE, relativize=True)
    monkeypatch.setattr(dns.query, "xfr", lambda *_a, **_kw: object())
    monkeypatch.setattr(dns.zone, "from_xfr", lambda _gen: served)

    on_wire = await axfr_zone_records(host="192.0.2.1", port=53, zone_name=_ZONE)
    by_name = {r.name: r for r in on_wire if r.record_type == "TXT"}
    for i, value in enumerate(_VALUES):
        db = RecordData(name=f"t{i}", record_type="TXT", value=value)
        assert _key(by_name[f"t{i}"], _ZONE, relative_targets=True) == _key(
            db, _ZONE, relative_targets=True
        ), value
    # A simple record still reads back as the plain text it is stored as.
    assert by_name["t0"].value == "v=spf1 -all"
    assert by_name["t2"].value == '"v=DKIM1; k=rsa; p=AAA" "BBB"'


# ── technitium_api ─────────────────────────────────────────────────────


def _technitium_holds(strings: list[bytes]) -> RecordData:
    """What ``pull_zone_records`` returns for a TXT the server holds as ``strings``."""
    value, _ = rdata_to_value(
        "TXT",
        {
            "text": b"".join(strings).decode("utf-8", "replace"),
            "characterStringsBase64": [base64.b64encode(s).decode() for s in strings],
        },
    )
    return RecordData(name="@", record_type="TXT", value=value, ttl=3600)


@pytest.mark.parametrize("value", [v for v in _VALUES if '""' not in v])
def test_technitium_api_write_reads_back_in_sync(value: str) -> None:
    """The strings sent are what the server holds and returns; the readback
    keys the same as the DB row. (Technitium drops empty strings, so the
    values carrying one are left out.)"""
    sent = record_params("TXT", value)["characterStringsBase64"].split(",")
    wire = _technitium_holds([base64.b64decode(s) for s in sent])
    db = RecordData(name="@", record_type="TXT", value=value)
    assert _key(wire, _ZONE, relative_targets=True) == _key(db, _ZONE, relative_targets=True)


def _zone() -> DNSZone:
    return DNSZone(id=uuid.uuid4(), name=_ZONE, group_id=uuid.uuid4())


def _row(zone: DNSZone, value: str) -> DNSRecord:
    return DNSRecord(
        zone_id=zone.id, name="@", fqdn="example.com", record_type="TXT", value=value, ttl=3600
    )


def _legacy_strings(value: str) -> list[bytes]:
    """What a technitium_api server holds for ``value`` written before #1760:
    the old write sent ``{"text": value.rstrip(".")}``, which Technitium
    stores as content cut every 255 octets (``DnsTXTRecordData(string)``)."""
    raw = value.rstrip(".").encode("utf-8")
    return [raw[i : i + 255] for i in range(0, len(raw), 255)]


_BROKEN = ['"v=spf1 -all"', '"v=DKIM1; k=rsa; p=AAA" "BBB"', "Hello."]


def test_sync_does_not_import_a_pre_1760_txt_as_a_new_row() -> None:
    zone = _zone()
    rows = [_row(zone, v) for v in [*_BROKEN, "google-site-verification=abc"]]
    on_wire = [_technitium_holds(_legacy_strings(r.value)) for r in rows]
    db_keys = {_key(r, zone.name, relative_targets=True) for r in rows}
    # Each broken record is served wrong: not in sync, so the push replaces it.
    assert sum(_key(w, zone.name, relative_targets=True) in db_keys for w in on_wire) == 1

    primary = SimpleNamespace(id=uuid.uuid4(), driver="technitium_api")
    result = _additive_import(
        None,  # apply=False never touches the session
        zone,
        on_wire,
        db_keys,
        apply=False,
        relative_targets=True,
        not_importable=_not_importable(primary, rows, zone.name),
    )
    assert result.imported == 0
    assert result.existing_in_db == 1


def test_only_technitium_api_skips_the_legacy_form() -> None:
    """No other driver ever wrote it: on BIND9 a TXT with literal quotes in
    its content is a real record, and is imported."""
    zone = _zone()
    rows = [_row(zone, '"v=spf1 -all"')]
    assert _not_importable(SimpleNamespace(driver="bind9"), rows, zone.name) == set()
    assert _not_importable(SimpleNamespace(driver="technitium_api"), rows, zone.name)


class _Session:
    """Stands in for the DB the push's RRset stamping reads."""

    def __init__(self, rows: list[DNSRecord]) -> None:
        self._rows = rows

    async def execute(self, _stmt: Any) -> Any:
        rows = self._rows
        return SimpleNamespace(scalars=lambda: SimpleNamespace(all=lambda: rows))


class _RecordingDriver:
    def __init__(self) -> None:
        self.applied: list[Any] = []

    def capabilities(self) -> dict[str, Any]:
        return {"record_types": ["TXT"]}

    async def apply_record_changes(self, server: Any, changes: list[Any]) -> list[Any]:
        self.applied.extend(changes)
        return [RecordChangeResult(ok=True, change=c) for c in changes]


async def test_sync_push_carries_the_whole_rrset() -> None:
    """technitium_api writes member 0 with ``overwrite=true``. Pushed alone,
    the repaired SPF would replace the in-sync verification TXT beside it,
    and the next Sync would push that back over the SPF."""
    zone = _zone()
    spf = _row(zone, '"v=spf1 -all"')
    verification = _row(zone, "google-site-verification=abc")
    on_wire = [
        _technitium_holds(_legacy_strings(spf.value)),
        _technitium_holds(_legacy_strings(verification.value)),
    ]
    driver = _RecordingDriver()
    primary = SimpleNamespace(id=uuid.uuid4(), driver="technitium_api")
    result = await _additive_push(
        _Session([spf, verification]),  # type: ignore[arg-type]
        primary,
        driver,
        zone,
        on_wire,
        [spf, verification],
        apply=True,
    )
    assert result.pushed == 1
    (change,) = driver.applied
    assert change.record.value == spf.value
    assert change.rrset is not None
    assert sorted(m.value for m in change.rrset.members) == sorted([spf.value, verification.value])
