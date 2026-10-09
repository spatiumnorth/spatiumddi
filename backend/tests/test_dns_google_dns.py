"""Unit tests for the Google Cloud DNS cloud DNS driver (issue #37).

All tests are offline: the ``google-cloud-dns`` SDK is not installed in
CI (it's an optional tier-3 dependency), so we

* monkeypatch the client factory (``_client``) to return a stub whose
  ``list_zones()`` yields ``SimpleNamespace`` managed-zone objects, and
* inject stub ``google.api_core.exceptions`` / ``google.auth.exceptions``
  modules into ``sys.modules`` so the driver's lazily-imported error
  wrapping resolves without the real SDK.

Nothing ever touches GCP.
"""

from __future__ import annotations

import sys
import types
from types import SimpleNamespace
from typing import Any

import pytest

from app.drivers.dns._cloud_base import CloudDNSError
from app.drivers.dns.base import RecordChange, RecordData
from app.drivers.dns.googledns import GoogleCloudDNSDriver

# ── Stub GCP exception modules (installed for the whole test module) ───────


class _GoogleAPICallError(Exception):
    """Stand-in for google.api_core.exceptions.GoogleAPICallError (offline)."""


class _GoogleAuthError(Exception):
    """Stand-in for google.auth.exceptions.GoogleAuthError (offline)."""


@pytest.fixture(autouse=True)
def _stub_google_modules() -> Any:
    """Make the driver's lazy ``from google... import exceptions`` resolve.

    The driver imports ``google.api_core.exceptions`` +
    ``google.auth.exceptions`` inside ``_wrap_call`` so the module imports
    cleanly without the SDK. Inject stub modules carrying our exception
    classes so the except clauses bind to types we can raise in tests.
    """
    created: list[str] = []
    for mod_name in (
        "google",
        "google.api_core",
        "google.api_core.exceptions",
        "google.auth",
        "google.auth.exceptions",
    ):
        if mod_name not in sys.modules:
            sys.modules[mod_name] = types.ModuleType(mod_name)
            created.append(mod_name)
    sys.modules["google.api_core.exceptions"].GoogleAPICallError = _GoogleAPICallError  # type: ignore[attr-defined]
    sys.modules["google.auth.exceptions"].GoogleAuthError = _GoogleAuthError  # type: ignore[attr-defined]
    yield
    for mod_name in created:
        sys.modules.pop(mod_name, None)


# ── Helpers ────────────────────────────────────────────────────────────────


def _server() -> SimpleNamespace:
    """A stand-in DNS server row (the driver only touches a few attrs)."""
    return SimpleNamespace(id="srv-1", name="gcp", credentials_encrypted=None)


CREDS = {"service_account_json": '{"type": "service_account"}', "project_id": "proj-1"}


def _patch_client(
    monkeypatch: pytest.MonkeyPatch, driver: GoogleCloudDNSDriver, client: Any
) -> None:
    """Wire ``driver._client`` to return ``client`` regardless of creds."""
    monkeypatch.setattr(driver, "_client", lambda creds: client)


def _rrset(name: str, rtype: str, ttl: int | None, rrdatas: list[str]) -> SimpleNamespace:
    """A stub Cloud DNS ``ResourceRecordSet``."""
    return SimpleNamespace(name=name, record_type=rtype, ttl=ttl, rrdatas=rrdatas)


class _StubChanges:
    """A stub Cloud DNS ``Changes`` transaction.

    Records ``add_record_set`` / ``delete_record_set`` calls, flips to
    ``done`` on ``create()`` so the driver's bounded poll loop returns on
    the first check.
    """

    def __init__(self) -> None:
        self.added: list[Any] = []
        self.deleted: list[Any] = []
        self.created = False
        self.status = "pending"

    def add_record_set(self, rrset: Any) -> None:
        self.added.append(rrset)

    def delete_record_set(self, rrset: Any) -> None:
        self.deleted.append(rrset)

    def create(self) -> None:
        self.created = True
        self.status = "done"

    def reload(self) -> None:  # pragma: no cover — done before first poll
        self.status = "done"


class _StubZone:
    """A stub Cloud DNS managed zone (``ManagedZone``)."""

    def __init__(
        self, name: str, dns_name: str, rrsets: list[SimpleNamespace] | None = None
    ) -> None:
        self.name = name  # GCP managed-zone id (slug)
        self.dns_name = dns_name  # FQDN
        self._rrsets = rrsets or []
        self.changes_obj = _StubChanges()
        self.created = False
        self.deleted = False
        # Capture the args to ``resource_record_set`` for assertions.
        self.built_rrsets: list[tuple[str, str, int, list[str]]] = []

    def list_resource_record_sets(self) -> list[SimpleNamespace]:
        return list(self._rrsets)

    def changes(self) -> _StubChanges:
        return self.changes_obj

    def resource_record_set(
        self, name: str, record_type: str, ttl: int, rrdatas: list[str]
    ) -> SimpleNamespace:
        self.built_rrsets.append((name, record_type, ttl, rrdatas))
        return _rrset(name, record_type, ttl, rrdatas)

    def create(self) -> None:
        self.created = True

    def delete(self) -> None:
        self.deleted = True


def _client_with_zones(*zones: _StubZone) -> SimpleNamespace:
    """A stub ``dns.Client`` whose ``list_zones()`` yields ``zones``."""
    return SimpleNamespace(
        list_zones=lambda: iter(zones),
        zone=lambda slug, dns_name=None: _StubZone(slug, dns_name or ""),
    )


# ── Zone listing ─────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_list_zones_name_and_reverse(monkeypatch: pytest.MonkeyPatch) -> None:
    driver = GoogleCloudDNSDriver()
    client = _client_with_zones(
        _StubZone("example-com", "example.com."),
        _StubZone("rev-10", "10.in-addr.arpa."),
    )
    _patch_client(monkeypatch, driver, client)

    zones = await driver._list_zones(_server(), CREDS)

    # ``name`` is the normalised DNS name; ``zone_id`` is the GCP slug.
    assert [z.name for z in zones] == ["example.com.", "10.in-addr.arpa."]
    assert [z.zone_id for z in zones] == ["example-com", "rev-10"]
    assert [z.is_reverse for z in zones] == [False, True]
    assert all(z.dnssec_enabled is False for z in zones)


@pytest.mark.asyncio
async def test_pull_zones_from_server_neutral_shape(monkeypatch: pytest.MonkeyPatch) -> None:
    driver = GoogleCloudDNSDriver()
    client = _client_with_zones(_StubZone("example-com", "Example.COM."))
    _patch_client(monkeypatch, driver, client)
    # Bypass credential decrypt — the base loads from credentials_encrypted.
    monkeypatch.setattr(driver, "_load_credentials", lambda server: CREDS)

    out = await driver.pull_zones_from_server(_server())

    assert out == [
        {
            "name": "example.com.",
            "zone_type": "Primary",
            "is_reverse_lookup": False,
            "dnssec_enabled": False,
            "zone_id": "example-com",
            "record_count": None,
        }
    ]


# ── Record listing / relativization / rrdata expansion ─────────────────────


@pytest.mark.asyncio
async def test_list_zone_records_expand_and_relativize(monkeypatch: pytest.MonkeyPatch) -> None:
    driver = GoogleCloudDNSDriver()
    zone = _StubZone(
        "example-com",
        "example.com.",
        rrsets=[
            _rrset("example.com.", "SOA", 21600, ["ns dns 1 2 3 4 5"]),  # skipped
            _rrset(
                "example.com.",
                "NS",
                172800,
                ["ns-cloud-a1.googledomains.com.", "ns-cloud-a2.googledomains.com."],
            ),
            _rrset("www.example.com.", "A", 300, ["10.0.0.1"]),
            _rrset("example.com.", "MX", 3600, ["10 mail.example.com."]),
        ],
    )
    client = _client_with_zones(zone)
    _patch_client(monkeypatch, driver, client)

    records = await driver._list_zone_records(_server(), CREDS, "example.com.")

    # SOA is skipped.
    assert all(r.record_type != "SOA" for r in records)

    # NS rrset with two rrdatas expands into two RecordData rows, apex → "@".
    ns = [r for r in records if r.record_type == "NS"]
    assert len(ns) == 2
    assert {r.value for r in ns} == {
        "ns-cloud-a1.googledomains.com.",
        "ns-cloud-a2.googledomains.com.",
    }
    assert all(r.name == "@" for r in ns)

    # www relativized to "www" with its TTL.
    www = next(r for r in records if r.record_type == "A")
    assert www.name == "www"
    assert www.value == "10.0.0.1"
    assert www.ttl == 300

    # MX rdata is split on read (#1526): bare target + preference column.
    mx = next(r for r in records if r.record_type == "MX")
    assert mx.value == "mail.example.com."
    assert mx.name == "@"
    assert mx.priority == 10


@pytest.mark.asyncio
async def test_list_zone_records_zone_not_found(monkeypatch: pytest.MonkeyPatch) -> None:
    driver = GoogleCloudDNSDriver()
    # Client returns a neighbouring zone, not the one we asked for.
    client = _client_with_zones(_StubZone("other-com", "other.com."))
    _patch_client(monkeypatch, driver, client)

    with pytest.raises(CloudDNSError, match="not found"):
        await driver._list_zone_records(_server(), CREDS, "example.com.")


# ── Record write: change-set build for create / update / delete ────────────


@pytest.mark.asyncio
async def test_apply_record_create_builds_add_change(monkeypatch: pytest.MonkeyPatch) -> None:
    driver = GoogleCloudDNSDriver()
    zone = _StubZone("example-com", "example.com.")
    client = _client_with_zones(zone)
    _patch_client(monkeypatch, driver, client)

    change = RecordChange(
        op="create",
        zone_name="example.com.",
        record=RecordData(name="www", record_type="A", value="10.0.0.1", ttl=120),
        target_serial=1,
    )
    await driver._apply_record(_server(), CREDS, change)

    ch = zone.changes_obj
    assert ch.created is True
    assert ch.deleted == []
    # The added rrset is the absolutized name + single-value rrdatas.
    assert zone.built_rrsets == [("www.example.com.", "A", 120, ["10.0.0.1"])]
    assert len(ch.added) == 1


@pytest.mark.asyncio
async def test_apply_record_apex_and_default_ttl(monkeypatch: pytest.MonkeyPatch) -> None:
    driver = GoogleCloudDNSDriver()
    zone = _StubZone("example-com", "example.com.")
    client = _client_with_zones(zone)
    _patch_client(monkeypatch, driver, client)

    change = RecordChange(
        op="create",
        zone_name="example.com.",
        record=RecordData(name="@", record_type="TXT", value="v=spf1 -all", ttl=None),
        target_serial=1,
    )
    await driver._apply_record(_server(), CREDS, change)

    # Apex absolutized to the zone FQDN, default TTL 300 when None.
    assert zone.built_rrsets == [("example.com.", "TXT", 300, ["v=spf1 -all"])]


@pytest.mark.asyncio
async def test_apply_record_update_deletes_old_then_adds_new(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    driver = GoogleCloudDNSDriver()
    existing = _rrset("www.example.com.", "A", 300, ["10.0.0.9"])
    zone = _StubZone("example-com", "example.com.", rrsets=[existing])
    client = _client_with_zones(zone)
    _patch_client(monkeypatch, driver, client)

    change = RecordChange(
        op="update",
        zone_name="example.com.",
        record=RecordData(name="www", record_type="A", value="10.0.0.1", ttl=600),
        target_serial=1,
    )
    await driver._apply_record(_server(), CREDS, change)

    ch = zone.changes_obj
    # One atomic change set: delete the exact existing rrset + add the new.
    assert ch.deleted == [existing]
    assert zone.built_rrsets == [("www.example.com.", "A", 600, ["10.0.0.1"])]
    assert len(ch.added) == 1
    assert ch.created is True


@pytest.mark.asyncio
async def test_apply_record_delete_existing(monkeypatch: pytest.MonkeyPatch) -> None:
    driver = GoogleCloudDNSDriver()
    existing = _rrset("old.example.com.", "A", 300, ["10.0.0.9"])
    zone = _StubZone("example-com", "example.com.", rrsets=[existing])
    client = _client_with_zones(zone)
    _patch_client(monkeypatch, driver, client)

    change = RecordChange(
        op="delete",
        zone_name="example.com.",
        record=RecordData(name="old", record_type="A", value="10.0.0.9", ttl=300),
        target_serial=1,
    )
    await driver._apply_record(_server(), CREDS, change)

    ch = zone.changes_obj
    # Delete references the exact existing rrset; nothing added.
    assert ch.deleted == [existing]
    assert ch.added == []
    assert ch.created is True


@pytest.mark.asyncio
async def test_apply_record_delete_missing_is_noop(monkeypatch: pytest.MonkeyPatch) -> None:
    driver = GoogleCloudDNSDriver()
    zone = _StubZone("example-com", "example.com.", rrsets=[])  # nothing to delete
    client = _client_with_zones(zone)
    _patch_client(monkeypatch, driver, client)

    change = RecordChange(
        op="delete",
        zone_name="example.com.",
        record=RecordData(name="ghost", record_type="A", value="10.0.0.9", ttl=300),
        target_serial=1,
    )
    # No raise — and no empty change set committed.
    await driver._apply_record(_server(), CREDS, change)

    ch = zone.changes_obj
    assert ch.created is False
    assert ch.added == []
    assert ch.deleted == []


# ── Record write: multi-value RRset read-merge (the #328 data-loss fix) ─────


@pytest.mark.asyncio
async def test_apply_record_create_merges_into_existing_rrset(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Creating a 2nd value for an existing {name,type} keeps the sibling.

    A round-robin A record: the rrset already holds 10.0.0.1; creating
    10.0.0.2 must write the FULL merged set, not drop the original.
    """
    driver = GoogleCloudDNSDriver()
    existing = _rrset("www.example.com.", "A", 300, ["10.0.0.1"])
    zone = _StubZone("example-com", "example.com.", rrsets=[existing])
    client = _client_with_zones(zone)
    _patch_client(monkeypatch, driver, client)

    change = RecordChange(
        op="create",
        zone_name="example.com.",
        record=RecordData(name="www", record_type="A", value="10.0.0.2", ttl=300),
        target_serial=1,
    )
    await driver._apply_record(_server(), CREDS, change)

    ch = zone.changes_obj
    assert ch.created is True
    # Old rrset deleted, merged rrset (both values) added — one atomic change.
    assert ch.deleted == [existing]
    assert zone.built_rrsets == [("www.example.com.", "A", 300, ["10.0.0.1", "10.0.0.2"])]
    assert len(ch.added) == 1


@pytest.mark.asyncio
async def test_apply_record_create_existing_value_is_noop(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Re-creating an already-present value writes nothing (idempotent)."""
    driver = GoogleCloudDNSDriver()
    existing = _rrset("www.example.com.", "A", 300, ["10.0.0.1"])
    zone = _StubZone("example-com", "example.com.", rrsets=[existing])
    client = _client_with_zones(zone)
    _patch_client(monkeypatch, driver, client)

    change = RecordChange(
        op="create",
        zone_name="example.com.",
        record=RecordData(name="www", record_type="A", value="10.0.0.1", ttl=300),
        target_serial=1,
    )
    await driver._apply_record(_server(), CREDS, change)

    ch = zone.changes_obj
    assert ch.created is False
    assert ch.added == []
    assert ch.deleted == []


@pytest.mark.asyncio
async def test_apply_record_create_uses_change_ttl_on_merge(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A merge applies the change's ttl across the whole rrset."""
    driver = GoogleCloudDNSDriver()
    existing = _rrset("@", "MX", 3600, ["10 mail1.example.com."])
    # Apex rrset is stored under the absolute apex FQDN.
    existing.name = "example.com."
    zone = _StubZone("example-com", "example.com.", rrsets=[existing])
    client = _client_with_zones(zone)
    _patch_client(monkeypatch, driver, client)

    change = RecordChange(
        op="create",
        zone_name="example.com.",
        record=RecordData(
            name="@", record_type="MX", value="mail2.example.com.", ttl=600, priority=20
        ),
        target_serial=1,
    )
    await driver._apply_record(_server(), CREDS, change)

    # Both MX values present, ttl from the change (600).
    assert zone.built_rrsets == [
        ("example.com.", "MX", 600, ["10 mail1.example.com.", "20 mail2.example.com."])
    ]


@pytest.mark.asyncio
async def test_apply_record_delete_one_of_two_leaves_other(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Deleting one value of a 2-value rrset re-writes the reduced set."""
    driver = GoogleCloudDNSDriver()
    existing = _rrset("www.example.com.", "A", 300, ["10.0.0.1", "10.0.0.2"])
    zone = _StubZone("example-com", "example.com.", rrsets=[existing])
    client = _client_with_zones(zone)
    _patch_client(monkeypatch, driver, client)

    change = RecordChange(
        op="delete",
        zone_name="example.com.",
        record=RecordData(name="www", record_type="A", value="10.0.0.1", ttl=300),
        target_serial=1,
    )
    await driver._apply_record(_server(), CREDS, change)

    ch = zone.changes_obj
    assert ch.created is True
    # Old (full) rrset deleted; reduced rrset (the surviving value) re-added.
    assert ch.deleted == [existing]
    assert zone.built_rrsets == [("www.example.com.", "A", 300, ["10.0.0.2"])]
    assert len(ch.added) == 1


@pytest.mark.asyncio
async def test_apply_record_delete_last_value_removes_rrset(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Deleting the only value removes the whole rrset (no re-add)."""
    driver = GoogleCloudDNSDriver()
    existing = _rrset("www.example.com.", "A", 300, ["10.0.0.1"])
    zone = _StubZone("example-com", "example.com.", rrsets=[existing])
    client = _client_with_zones(zone)
    _patch_client(monkeypatch, driver, client)

    change = RecordChange(
        op="delete",
        zone_name="example.com.",
        record=RecordData(name="www", record_type="A", value="10.0.0.1", ttl=300),
        target_serial=1,
    )
    await driver._apply_record(_server(), CREDS, change)

    ch = zone.changes_obj
    assert ch.created is True
    assert ch.deleted == [existing]
    assert ch.added == []
    assert zone.built_rrsets == []


@pytest.mark.asyncio
async def test_apply_record_delete_value_not_in_rrset_is_noop(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Deleting a value absent from the live rrset is an idempotent no-op."""
    driver = GoogleCloudDNSDriver()
    existing = _rrset("www.example.com.", "A", 300, ["10.0.0.1", "10.0.0.2"])
    zone = _StubZone("example-com", "example.com.", rrsets=[existing])
    client = _client_with_zones(zone)
    _patch_client(monkeypatch, driver, client)

    change = RecordChange(
        op="delete",
        zone_name="example.com.",
        record=RecordData(name="www", record_type="A", value="10.0.0.9", ttl=300),
        target_serial=1,
    )
    await driver._apply_record(_server(), CREDS, change)

    ch = zone.changes_obj
    assert ch.created is False
    assert ch.added == []
    assert ch.deleted == []


@pytest.mark.asyncio
async def test_apply_record_bad_op(monkeypatch: pytest.MonkeyPatch) -> None:
    driver = GoogleCloudDNSDriver()
    _patch_client(monkeypatch, driver, _client_with_zones(_StubZone("z", "x.test.")))
    change = RecordChange(
        op="rename",  # type: ignore[arg-type]
        zone_name="x.test.",
        record=RecordData(name="a", record_type="A", value="1.2.3.4", ttl=300),
        target_serial=1,
    )
    with pytest.raises(CloudDNSError, match="bad op"):
        await driver._apply_record(_server(), CREDS, change)


# ── Zone write ─────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_apply_zone_create(monkeypatch: pytest.MonkeyPatch) -> None:
    driver = GoogleCloudDNSDriver()
    created_zones: list[_StubZone] = []

    def _zone_factory(slug: str, dns_name: str | None = None) -> _StubZone:
        z = _StubZone(slug, dns_name or "")
        created_zones.append(z)
        return z

    client = SimpleNamespace(list_zones=lambda: iter(()), zone=_zone_factory)
    _patch_client(monkeypatch, driver, client)

    zone = SimpleNamespace(name="New.Example.")
    await driver._apply_zone(_server(), CREDS, zone, "create")

    assert len(created_zones) == 1
    made = created_zones[0]
    # Slug derived from the FQDN; dns_name is the normalised FQDN.
    assert made.name == "new-example"
    assert made.dns_name == "new.example."
    assert made.created is True


@pytest.mark.asyncio
async def test_apply_zone_delete_resolves_zone(monkeypatch: pytest.MonkeyPatch) -> None:
    driver = GoogleCloudDNSDriver()
    target = _StubZone("doomed-example", "doomed.example.")
    client = _client_with_zones(target)
    _patch_client(monkeypatch, driver, client)

    zone = SimpleNamespace(name="doomed.example.")
    await driver._apply_zone(_server(), CREDS, zone, "delete")

    assert target.deleted is True


@pytest.mark.asyncio
async def test_apply_zone_delete_empties_only_managed_records(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """#1528 — zone emptying is scoped to records SpatiumDDI manages.

    The managed www A + delegated sub-zone NS rrsets are deleted; the
    foreign TXT rrset (in the provider zone but NOT in our DB) must
    NOT appear in the change set; SOA / apex NS are always skipped.
    """
    driver = GoogleCloudDNSDriver()
    soa = _rrset("doomed.example.", "SOA", 21600, ["ns dns 1 2 3 4 5"])
    apex_ns = _rrset("doomed.example.", "NS", 172800, ["ns-cloud.googledomains.com."])
    www = _rrset("www.doomed.example.", "A", 300, ["10.0.0.1"])
    sub_ns = _rrset("sub.doomed.example.", "NS", 300, ["ns.other.example."])
    foreign_txt = _rrset("doomed.example.", "TXT", 300, ['"v=spf1 -all"'])
    target = _StubZone(
        "doomed-example", "doomed.example.", rrsets=[soa, apex_ns, www, sub_ns, foreign_txt]
    )
    client = _client_with_zones(target)
    _patch_client(monkeypatch, driver, client)

    zone = SimpleNamespace(name="doomed.example.")
    managed = [
        RecordData(name="www", record_type="A", value="10.0.0.1", ttl=300),
        RecordData(name="sub", record_type="NS", value="ns.other.example.", ttl=300),
    ]
    await driver._apply_zone(_server(), CREDS, zone, "delete", managed_records=managed)

    ch = target.changes_obj
    assert ch.created is True
    # Only the managed rrsets were deleted — the foreign TXT survives.
    assert ch.deleted == [www, sub_ns]
    assert ch.added == []
    assert target.deleted is True


@pytest.mark.asyncio
async def test_apply_zone_delete_mixed_rrset_keeps_foreign_value(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A managed value sharing an rrset with a foreign value: the rrset
    is replaced with just the foreign value, never dropped wholesale."""
    driver = GoogleCloudDNSDriver()
    mixed = _rrset("rr.doomed.example.", "A", 300, ["10.0.0.1", "10.0.0.2"])
    target = _StubZone("doomed-example", "doomed.example.", rrsets=[mixed])
    client = _client_with_zones(target)
    _patch_client(monkeypatch, driver, client)

    zone = SimpleNamespace(name="doomed.example.")
    managed = [RecordData(name="rr", record_type="A", value="10.0.0.1", ttl=300)]
    await driver._apply_zone(_server(), CREDS, zone, "delete", managed_records=managed)

    ch = target.changes_obj
    assert ch.created is True
    assert ch.deleted == [mixed]
    # Reduced rrset re-added carrying ONLY the foreign value.
    assert target.built_rrsets == [("rr.doomed.example.", "A", 300, ["10.0.0.2"])]
    assert len(ch.added) == 1
    assert target.deleted is True


@pytest.mark.asyncio
async def test_apply_zone_delete_foreign_only_zone_deletes_no_records(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """We manage nothing in the zone → the emptying commits no change
    set at all; foreign records are left exactly as they are."""
    driver = GoogleCloudDNSDriver()
    foreign = _rrset("www.doomed.example.", "A", 300, ["10.0.0.1"])
    target = _StubZone("doomed-example", "doomed.example.", rrsets=[foreign])
    client = _client_with_zones(target)
    _patch_client(monkeypatch, driver, client)

    zone = SimpleNamespace(name="doomed.example.")
    await driver._apply_zone(_server(), CREDS, zone, "delete", managed_records=[])

    ch = target.changes_obj
    assert ch.created is False
    assert ch.deleted == []
    assert ch.added == []


@pytest.mark.asyncio
async def test_apply_zone_delete_without_scoping_deletes_no_records(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """managed_records=None (caller supplied no scoping): no record is
    deleted on the way out — only the zone delete itself is attempted."""
    driver = GoogleCloudDNSDriver()
    populated = _StubZone(
        "doomed-example",
        "doomed.example.",
        rrsets=[_rrset("www.doomed.example.", "A", 300, ["10.0.0.1"])],
    )
    client = _client_with_zones(populated)
    _patch_client(monkeypatch, driver, client)

    zone = SimpleNamespace(name="doomed.example.")
    await driver._apply_zone(_server(), CREDS, zone, "delete")

    assert populated.changes_obj.created is False
    assert populated.deleted is True


@pytest.mark.asyncio
async def test_apply_zone_delete_absent_zone_is_success(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """#1528 — deleting a zone that is already gone is a no-op success."""
    driver = GoogleCloudDNSDriver()
    client = _client_with_zones(_StubZone("other-com", "other.com."))
    _patch_client(monkeypatch, driver, client)

    zone = SimpleNamespace(name="gone.example.")
    # No raise.
    await driver._apply_zone(_server(), CREDS, zone, "delete")


@pytest.mark.asyncio
async def test_apply_zone_bad_op(monkeypatch: pytest.MonkeyPatch) -> None:
    driver = GoogleCloudDNSDriver()
    _patch_client(monkeypatch, driver, _client_with_zones())
    with pytest.raises(CloudDNSError, match="unsupported op"):
        await driver._apply_zone(_server(), CREDS, SimpleNamespace(name="x.test."), "rename")


# ── Error wrapping ─────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_list_zones_wraps_google_api_error(monkeypatch: pytest.MonkeyPatch) -> None:
    driver = GoogleCloudDNSDriver()

    def _boom() -> Any:
        raise _GoogleAPICallError("permission denied")

    client = SimpleNamespace(list_zones=_boom, zone=lambda *a, **k: None)
    _patch_client(monkeypatch, driver, client)

    with pytest.raises(CloudDNSError, match="list_zones failed"):
        await driver._list_zones(_server(), CREDS)


@pytest.mark.asyncio
async def test_apply_record_wraps_google_auth_error(monkeypatch: pytest.MonkeyPatch) -> None:
    driver = GoogleCloudDNSDriver()

    class _AuthZone(_StubZone):
        def changes(self) -> _StubChanges:
            raise _GoogleAuthError("invalid credentials")

    zone = _AuthZone("example-com", "example.com.")
    client = _client_with_zones(zone)
    _patch_client(monkeypatch, driver, client)

    change = RecordChange(
        op="create",
        zone_name="example.com.",
        record=RecordData(name="www", record_type="A", value="10.0.0.1", ttl=120),
        target_serial=1,
    )
    with pytest.raises(CloudDNSError, match="change_record_sets failed"):
        await driver._apply_record(_server(), CREDS, change)


# ── Capabilities + credential fields ───────────────────────────────────────


def test_capabilities_shape() -> None:
    caps = GoogleCloudDNSDriver().capabilities()
    assert caps["name"] == "google_dns"
    assert caps["agentless"] is True
    assert caps["manages_zones"] is True
    assert caps["dnssec_online"] is False  # #29 — cloud DNSSEC deferred
    assert caps["views"] is False
    assert caps["rpz"] is False
    assert "A" in caps["record_types"]
    assert "SOA" in caps["record_types"]


def test_credential_fields() -> None:
    driver = GoogleCloudDNSDriver()
    assert driver.name == "google_dns"
    assert driver.credential_fields == ("service_account_json", "project_id")


# ── MX / SRV split-form contract (#1526) ────────────────────────────────────


@pytest.mark.asyncio
async def test_apply_record_create_srv_composes_all_fields(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An API-shaped SRV (bare target + priority/weight/port columns) goes
    out as the composed rdata string Cloud DNS stores."""
    driver = GoogleCloudDNSDriver()
    zone = _StubZone("example-com", "example.com.", rrsets=[])
    client = _client_with_zones(zone)
    _patch_client(monkeypatch, driver, client)

    change = RecordChange(
        op="create",
        zone_name="example.com.",
        record=RecordData(
            name="_sip._tcp",
            record_type="SRV",
            value="sip.example.com.",
            ttl=600,
            priority=10,
            weight=20,
            port=5060,
        ),
        target_serial=1,
    )
    await driver._apply_record(_server(), CREDS, change)

    assert zone.built_rrsets == [
        ("_sip._tcp.example.com.", "SRV", 600, ["10 20 5060 sip.example.com."])
    ]


@pytest.mark.asyncio
async def test_list_zone_records_splits_srv(monkeypatch: pytest.MonkeyPatch) -> None:
    driver = GoogleCloudDNSDriver()
    zone = _StubZone(
        "example-com",
        "example.com.",
        rrsets=[_rrset("_sip._tcp.example.com.", "SRV", 3600, ["10 20 5060 sip.example.com."])],
    )
    client = _client_with_zones(zone)
    _patch_client(monkeypatch, driver, client)

    records = await driver._list_zone_records(_server(), CREDS, "example.com.")
    assert records == [
        RecordData(
            name="_sip._tcp",
            record_type="SRV",
            value="sip.example.com.",
            ttl=3600,
            priority=10,
            weight=20,
            port=5060,
        )
    ]
