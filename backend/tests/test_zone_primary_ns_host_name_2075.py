"""#2075 — a zone's Primary NS (SOA MNAME) must be a host name.

BIND's check-names refuses a zone whose MNAME has an underscore or an over-long
label, so one such zone stopped its group applying. The REST schemas, the
Copilot create args and the importer all hold the same rule.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from app.api.v1.dns.router import ZoneCreate, ZoneUpdate
from app.core.dns_names import primary_ns_error
from app.services.ai.operations import CreateDNSZoneArgs
from app.services.dns_import.canonical import ImportedSOA, ImportedZone
from app.services.dns_import.commit import _zone_kwargs_from_parsed

BAD = [
    "ns_1.example.test.",
    "a" * 64 + ".example.test.",
    "ns1",
    "ns1.",
    "ns1..example.test.",
    ".example.test.",
    "-ns1.example.test.",
    "ns1.example.test..",
]
GOOD = ["", "ns1.example.test.", "ns1.example.test", "NS1.Other-Corp.net.", "a" * 63 + ".test."]


@pytest.mark.parametrize("value", BAD)
def test_helper_refuses(value: str) -> None:
    assert primary_ns_error(value) is not None


@pytest.mark.parametrize("value", GOOD)
def test_helper_accepts(value: str) -> None:
    assert primary_ns_error(value) is None


@pytest.mark.parametrize("value", BAD)
def test_zone_create_422_names_the_field(value: str) -> None:
    with pytest.raises(ValidationError) as ei:
        ZoneCreate(name="z.test", primary_ns=value)
    errs = ei.value.errors()
    assert errs[0]["loc"] == ("primary_ns",)
    assert "Primary NS" in errs[0]["msg"]


@pytest.mark.parametrize("value", BAD)
def test_zone_update_refuses(value: str) -> None:
    with pytest.raises(ValidationError):
        ZoneUpdate(primary_ns=value)


def test_zone_schemas_accept_good_and_unset() -> None:
    assert ZoneCreate(name="z.test", primary_ns="ns1.z.test.").primary_ns == "ns1.z.test."
    assert ZoneCreate(name="z.test").primary_ns == ""
    assert ZoneUpdate().primary_ns is None
    assert ZoneUpdate(primary_ns="").primary_ns == ""


def test_admin_email_is_not_held_to_the_host_name_rule() -> None:
    # RNAME is a mailbox, not a host: an underscore is legal there.
    assert ZoneCreate(name="z.test", admin_email="host_master.z.test.").admin_email


def test_copilot_create_refuses_a_bad_primary_ns() -> None:
    with pytest.raises(ValidationError):
        CreateDNSZoneArgs(name="z.test", primary_ns="ns_1.z.test.")


def _parsed(mname: str) -> ImportedZone:
    soa = ImportedSOA(
        primary_ns=mname,
        admin_email="h.z.test.",
        serial=1,
        refresh=1,
        retry=1,
        expire=1,
        minimum=1,
        ttl=1,
    )
    return ImportedZone(name="z.test.", zone_type="primary", kind="forward", soa=soa, records=[])


@pytest.mark.parametrize(
    ("mname", "stored"),
    [("ns_1.z.test.", ""), ("ns1.z.test.", "ns1.z.test")],
)
def test_importer_does_not_store_an_unservable_mname(mname: str, stored: str) -> None:
    kw = _zone_kwargs_from_parsed(
        _parsed(mname),
        name="z.test.",
        target_group_id=uuid.uuid4(),
        target_view_id=None,
        source="bind9",  # type: ignore[arg-type]
        now=datetime.now(UTC),
    )
    assert kw["primary_ns"] == stored
