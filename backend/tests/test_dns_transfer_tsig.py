"""#734 — the control plane could never read a zone off agent-managed BIND9.

The #61 drift report and sync-with-servers both AXFR the live zone. The
agent grants ``allow-transfer`` to the group's TSIG **key**, never to a
source address, and the control plane transferred unsigned — so both
features failed with REFUSED on every zone of the flagship deployment,
100% of the time, for two releases.

Verified live against the dev BIND9 on a stock ``allow_transfer: ["none"]``
group while writing these: unsigned → ``REFUSED``; signed with the group
key → the zone came back. These tests pin the two halves that made that
work — picking a key the agent actually granted, and refusing to guess when
there isn't one.
"""

from __future__ import annotations

import base64
import uuid
from typing import Any

import dns.tsig
import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.dns.router import _TSIG_NAME_RE
from app.core.crypto import encrypt_str
from app.drivers.dns import AXFR_TSIG_DRIVERS, register_driver
from app.drivers.dns.base import RecordData, TsigKey
from app.models.dns import DNSRecord, DNSServer, DNSServerGroup, DNSTSIGKey, DNSView, DNSZone
from app.services.dns.agent_config import build_config_bundle
from app.services.dns.drift import compute_zone_drift
from app.services.dns.pull_from_server import pull_zone_from_server
from app.services.dns.tsig import (
    VIEW_TRANSFER_KEY_PREFIX,
    resolve_group_transfer_key,
    resolve_view_transfer_key,
    transfer_needs_tsig,
    view_transfer_key,
)

_B64 = "c2VjcmV0c2VjcmV0c2VjcmV0c2VjcmV0MDE="


async def _group(db: AsyncSession, **kw: Any) -> DNSServerGroup:
    grp = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:8]}", **kw)
    db.add(grp)
    await db.flush()
    return grp


# ── Which key gets used ─────────────────────────────────────────────────────


async def test_legacy_group_key_is_preferred(db_session: AsyncSession) -> None:
    """The auto-generated group key exists on every agent-managed group
    without operator action, so drift has to work out of the box rather
    than only after someone thinks to create a named key."""
    grp = await _group(
        db_session,
        tsig_key_name="spatium-default",
        tsig_key_secret=_B64,
        tsig_key_algorithm="hmac-sha512",
    )
    db_session.add(
        DNSTSIGKey(
            group_id=grp.id,
            name="aaa-operator-key",
            algorithm="hmac-sha256",
            secret_encrypted=encrypt_str(_B64),
        )
    )
    await db_session.flush()

    key = await resolve_group_transfer_key(db_session, grp.id)
    assert key is not None
    assert key.name == "spatium-default"
    # The group's own algorithm, not the default: signing with the wrong
    # algorithm fails as PeerBadKey, which reads like a permissions problem.
    assert key.algorithm == "hmac-sha512"


async def test_falls_back_to_first_operator_key_by_name(db_session: AsyncSession) -> None:
    """Without a legacy key, use the head of the same list the bundle ships.

    ``build_agent_bundle`` orders operator keys by name, and the agent grants
    every key in that list, so picking the first by name keeps both ends in
    agreement by construction.
    """
    grp = await _group(db_session)
    for name in ("zzz-last", "aaa-first"):
        db_session.add(
            DNSTSIGKey(
                group_id=grp.id,
                name=name,
                algorithm="hmac-sha256",
                secret_encrypted=encrypt_str(_B64),
            )
        )
    await db_session.flush()

    key = await resolve_group_transfer_key(db_session, grp.id)
    assert key is not None
    assert key.name == "aaa-first"


async def test_no_key_at_all_returns_none(db_session: AsyncSession) -> None:
    grp = await _group(db_session)
    assert await resolve_group_transfer_key(db_session, grp.id) is None


async def test_undecryptable_key_is_skipped_not_fatal(db_session: AsyncSession) -> None:
    """A row whose secret won't decrypt is also skipped from the bundle, so
    the agent never granted it — skip it here too and try the next one,
    rather than failing the whole report over one bad row."""
    grp = await _group(db_session)
    db_session.add(
        DNSTSIGKey(
            group_id=grp.id,
            name="aaa-broken",
            algorithm="hmac-sha256",
            secret_encrypted=b"not-a-valid-fernet-token",
        )
    )
    db_session.add(
        DNSTSIGKey(
            group_id=grp.id,
            name="bbb-good",
            algorithm="hmac-sha256",
            secret_encrypted=encrypt_str(_B64),
        )
    )
    await db_session.flush()

    key = await resolve_group_transfer_key(db_session, grp.id)
    assert key is not None
    assert key.name == "bbb-good"


async def test_partial_legacy_key_is_not_used(db_session: AsyncSession) -> None:
    """A name with no secret can't sign anything. Half a key is no key."""
    grp = await _group(db_session, tsig_key_name="spatium-default", tsig_key_secret=None)
    assert await resolve_group_transfer_key(db_session, grp.id) is None


# ── What the drift report does with it ──────────────────────────────────────


class _RecordingDriver:
    """Captures the ``tsig`` kwarg the drift service hands the driver."""

    seen: list[Any] = []

    async def pull_zone_records(
        self, server: Any, zone_name: str, *, tsig: Any = None
    ) -> list[RecordData]:
        type(self).seen.append(tsig)
        return []


async def _zone_with_server(
    db_session: AsyncSession,
    grp: DNSServerGroup,
    driver: str,
    *,
    agent_managed: bool = True,
) -> DNSZone:
    db_session.add(
        DNSServer(
            group_id=grp.id,
            name=f"srv-{uuid.uuid4().hex[:6]}",
            host="192.0.2.10",
            driver=driver,
            is_primary=True,
            # Set only by ``POST /dns/agents/register`` — the marker that an
            # agent actually rendered this server's named.conf, and therefore
            # granted the key-gated allow-transfer.
            agent_id=uuid.uuid4() if agent_managed else None,
        )
    )
    zone = DNSZone(group_id=grp.id, name="example.com.", zone_type="primary")
    db_session.add(zone)
    await db_session.flush()
    return zone


@pytest.fixture
def recording_driver() -> type[_RecordingDriver]:
    _RecordingDriver.seen = []
    register_driver("bind9", _RecordingDriver)  # type: ignore[arg-type]
    register_driver("windows_dns", _RecordingDriver)  # type: ignore[arg-type]
    yield _RecordingDriver
    # Restore the real drivers so later tests in the session aren't affected.
    from app.drivers.dns.bind9 import BIND9Driver
    from app.drivers.dns.windows import WindowsDNSDriver

    register_driver("bind9", BIND9Driver)
    register_driver("windows_dns", WindowsDNSDriver)


async def test_drift_signs_for_an_agent_managed_server(
    db_session: AsyncSession, recording_driver: type[_RecordingDriver]
) -> None:
    """The fix, end to end through the service: bind9 gets the group key."""
    grp = await _group(db_session, tsig_key_name="spatium-default", tsig_key_secret=_B64)
    zone = await _zone_with_server(db_session, grp, "bind9")

    report = await compute_zone_drift(db_session, group_id=grp.id, zone=zone)

    assert [s.status for s in report.servers] == ["ok"]
    assert recording_driver.seen[0] is not None
    assert recording_driver.seen[0].name == "spatium-default"


async def test_drift_does_not_sign_for_windows(
    db_session: AsyncSession, recording_driver: type[_RecordingDriver]
) -> None:
    """Windows authorises transfers by address and knows nothing of our
    group key. Handing it one turns a WORKING unsigned pull into BADKEY —
    a regression introduced by the fix, in a driver the fix isn't about."""
    grp = await _group(db_session, tsig_key_name="spatium-default", tsig_key_secret=_B64)
    zone = await _zone_with_server(db_session, grp, "windows_dns")

    await compute_zone_drift(db_session, group_id=grp.id, zone=zone)

    assert recording_driver.seen == [None]


async def test_drift_fails_closed_and_names_the_missing_key(
    db_session: AsyncSession, recording_driver: type[_RecordingDriver]
) -> None:
    """No key means the transfer cannot succeed. Say which thing is missing.

    The generic REFUSED error points at allow-transfer and the firewall —
    neither is the problem, and neither is reachable anyway, because the
    agent owns named.conf. That dead end is what made this issue's symptom
    unactionable for the operator.
    """
    grp = await _group(db_session)
    zone = await _zone_with_server(db_session, grp, "bind9")

    report = await compute_zone_drift(db_session, group_id=grp.id, zone=zone)

    (entry,) = report.servers
    assert entry.status == "unsupported"
    assert entry.error is not None
    assert "TSIG key" in entry.error
    assert "allow-transfer" not in entry.error
    # And it must not have attempted a transfer that could only fail.
    assert recording_driver.seen == []


def test_windows_is_deliberately_not_a_tsig_driver() -> None:
    """Pin the taxonomy itself — adding windows_dns here would silently
    break every working Windows Path A pull."""
    assert AXFR_TSIG_DRIVERS == {"bind9", "technitium"}


# ── Agent-managed vs operator-run ───────────────────────────────────────────
#
# The driver name alone does NOT decide this. A ``bind9`` row can be an
# operator's own BIND9 that SpatiumDDI never deployed to — pointed at by
# host, authorised the ordinary way by address. That server has no group key
# and never granted one, so signing its transfer turns a working unsigned
# pull into NOTAUTH, and refusing to pull for want of a key breaks it a
# different way. ``agent_id`` separates the two.


def _srv(driver: str, agent_id: uuid.UUID | None) -> DNSServer:
    return DNSServer(name="s", host="192.0.2.10", driver=driver, agent_id=agent_id)


@pytest.mark.parametrize(
    ("driver", "agent_managed", "expected"),
    [
        ("bind9", True, True),
        ("technitium", True, True),
        # The regression this guards: an operator-run BIND9 must keep its
        # unsigned, address-authorised pull.
        ("bind9", False, False),
        ("technitium", False, False),
        # Windows authorises by address even when agent-adjacent.
        ("windows_dns", True, False),
        ("cloudflare", False, False),
    ],
)
def test_only_agent_managed_axfr_drivers_need_signing(
    driver: str, agent_managed: bool, expected: bool
) -> None:
    server = _srv(driver, uuid.uuid4() if agent_managed else None)
    assert transfer_needs_tsig(server) is expected


async def test_drift_leaves_an_operator_run_bind9_unsigned(
    db_session: AsyncSession, recording_driver: type[_RecordingDriver]
) -> None:
    """End to end: a keyed group must not sign for a server no agent owns."""
    grp = await _group(db_session, tsig_key_name="spatium-default", tsig_key_secret=_B64)
    zone = await _zone_with_server(db_session, grp, "bind9", agent_managed=False)

    report = await compute_zone_drift(db_session, group_id=grp.id, zone=zone)

    assert [s.status for s in report.servers] == ["ok"]
    assert recording_driver.seen == [None]


async def test_operator_run_bind9_is_not_blocked_by_a_missing_key(
    db_session: AsyncSession, recording_driver: type[_RecordingDriver]
) -> None:
    """A keyless group is fine here — this server never needed a key. Failing
    closed would be the fix breaking a pull that worked before it."""
    grp = await _group(db_session)
    zone = await _zone_with_server(db_session, grp, "bind9", agent_managed=False)

    report = await compute_zone_drift(db_session, group_id=grp.id, zone=zone)

    assert [s.status for s in report.servers] == ["ok"]
    assert recording_driver.seen == [None]


# ── #920: split-horizon — address the transfer to the zone's own view ───────
#
# BIND picks the view for a request by match-clients BEFORE it consults
# allow-transfer, and the operator's client lists never name the control
# plane. Signed with the group key, a drift / sync transfer matched no view
# (BADKEY — "the key is unknown", for a key that was loaded and granted) or
# was caught by a broad view and read that view's copy. Each view now admits
# a key of its own, derived from the legacy group key; these tests pin the
# control-plane half: which key, derived how, and what happens when an agent
# does not know it yet.

_LEGACY = TsigKey(name="spatium-default", algorithm="hmac-sha256", secret=_B64)


def test_view_transfer_keys_are_deterministic_distinct_and_namespaced() -> None:
    a = view_transfer_key(_LEGACY, "internal")
    assert a == view_transfer_key(_LEGACY, "internal")
    b = view_transfer_key(_LEGACY, "external")
    assert (a.name, a.secret) != (b.name, b.secret)
    # Case matters to a view name and not to a TSIG key name (a DNS name), so
    # the name is a digest rather than the view name folded to lower case.
    assert view_transfer_key(_LEGACY, "Internal").name != a.name
    # Never the group secret, and a different group key gives different keys.
    assert a.secret != _LEGACY.secret
    other = TsigKey(name="spatium-other", algorithm="hmac-sha256", secret="b3RoZXI=")
    assert view_transfer_key(other, "internal").secret != a.secret
    # A full-strength hmac-sha256 key the agent renders as-is.
    assert a.algorithm == "hmac-sha256"
    assert len(base64.b64decode(a.secret, validate=True)) == 32
    # A namespace no existing key can occupy: operator key names may not
    # contain "_" (the router's own validator), and the legacy group key is
    # "spatium-<label>". A clash would be two ``key`` statements with one
    # name — a config BIND refuses whole.
    assert a.name.startswith(VIEW_TRANSFER_KEY_PREFIX)
    assert not _TSIG_NAME_RE.match(a.name)
    assert not a.name.startswith("spatium-")


async def _views_group(
    db_session: AsyncSession, *, legacy: bool = True
) -> tuple[DNSServerGroup, DNSView, DNSView]:
    grp = (
        await _group(db_session, tsig_key_name=_LEGACY.name, tsig_key_secret=_B64)
        if legacy
        else await _group(db_session)
    )
    first = DNSView(group_id=grp.id, name="internal", match_clients=["10.0.0.0/8"], order=0)
    second = DNSView(group_id=grp.id, name="lab", match_clients=["192.0.2.0/24"], order=10)
    db_session.add_all([first, second])
    await db_session.flush()
    return grp, first, second


async def test_a_zone_pinned_to_a_view_is_read_through_that_view(
    db_session: AsyncSession, recording_driver: type[_RecordingDriver]
) -> None:
    grp, _first, lab = await _views_group(db_session)
    zone = await _zone_with_server(db_session, grp, "bind9")
    zone.view_id = lab.id
    await db_session.flush()

    report = await compute_zone_drift(db_session, group_id=grp.id, zone=zone)

    assert [s.status for s in report.servers] == ["ok"]
    assert recording_driver.seen == [view_transfer_key(_LEGACY, "lab")]


async def test_a_zone_in_every_view_is_read_through_the_first(
    db_session: AsyncSession, recording_driver: type[_RecordingDriver]
) -> None:
    """A zone with no view scoping renders into every view with the same
    records; the first in precedence order is as good as any, and stable."""
    grp, _first, _lab = await _views_group(db_session)
    zone = await _zone_with_server(db_session, grp, "bind9")

    await compute_zone_drift(db_session, group_id=grp.id, zone=zone)

    assert recording_driver.seen == [view_transfer_key(_LEGACY, "internal")]


async def test_a_zone_scoped_by_its_records_is_read_through_a_view_that_holds_it(
    db_session: AsyncSession, recording_driver: type[_RecordingDriver]
) -> None:
    """A view-scoped record confines the zone to that view (#24's expansion
    rule). Asking the first view for it would get NOTAUTH."""
    grp, _first, lab = await _views_group(db_session)
    zone = await _zone_with_server(db_session, grp, "bind9")
    db_session.add(
        DNSRecord(
            zone_id=zone.id, view_id=lab.id, name="lab-only", record_type="A", value="192.0.2.7"
        )
    )
    await db_session.flush()

    await compute_zone_drift(db_session, group_id=grp.id, zone=zone)

    assert recording_driver.seen == [view_transfer_key(_LEGACY, "lab")]


async def test_without_a_legacy_key_a_views_group_signs_as_before(
    db_session: AsyncSession, recording_driver: type[_RecordingDriver]
) -> None:
    """An operator key is never a derivation base — its secret is in the
    operator's DDNS clients, which could then compute a key selecting any
    view. Such a group keeps the pre-#920 behaviour."""
    grp, internal, _lab = await _views_group(db_session, legacy=False)
    db_session.add(
        DNSTSIGKey(
            group_id=grp.id,
            name="aaa-operator-key",
            algorithm="hmac-sha256",
            secret_encrypted=encrypt_str(_B64),
        )
    )
    zone = await _zone_with_server(db_session, grp, "bind9")
    zone.view_id = internal.id
    await db_session.flush()

    await compute_zone_drift(db_session, group_id=grp.id, zone=zone)

    assert [k.name for k in recording_driver.seen] == ["aaa-operator-key"]


async def test_the_bundle_ships_exactly_the_key_the_resolver_signs_with(
    db_session: AsyncSession,
) -> None:
    """The two ends of #920 agree by construction. Pin the construction."""
    grp, _internal, lab = await _views_group(db_session)
    zone = await _zone_with_server(db_session, grp, "bind9")
    zone.view_id = lab.id
    await db_session.flush()
    server = (
        await db_session.execute(select(DNSServer).where(DNSServer.group_id == grp.id))
    ).scalar_one()

    bundle = await build_config_bundle(db_session, server)
    shipped = {v["name"]: v["transfer_key"] for v in bundle["views"]}
    resolved = await resolve_view_transfer_key(db_session, zone)

    assert resolved is not None
    key, view_name = resolved
    assert view_name == "lab"
    assert set(shipped) == {"internal", "lab"}
    assert shipped["lab"] == {"name": key.name, "secret": key.secret, "algorithm": key.algorithm}


async def test_no_view_keys_ship_without_a_legacy_key(db_session: AsyncSession) -> None:
    grp, _internal, _lab = await _views_group(db_session, legacy=False)
    await _zone_with_server(db_session, grp, "bind9")
    server = (
        await db_session.execute(select(DNSServer).where(DNSServer.group_id == grp.id))
    ).scalar_one()

    bundle = await build_config_bundle(db_session, server)

    assert [v["name"] for v in bundle["views"]] == ["internal", "lab"]
    assert all("transfer_key" not in v for v in bundle["views"])


class _PredatesViewKeysDriver:
    """An agent that never rendered the view keys: it answers BADKEY to any
    key but the ones in ``accepts``, the way BIND does to an unknown key."""

    seen: list[Any] = []
    accepts: set[str] = set()
    other_failure: str | None = None

    async def pull_zone_records(
        self, server: Any, zone_name: str, *, tsig: Any = None
    ) -> list[RecordData]:
        type(self).seen.append(tsig)
        if type(self).other_failure is not None:
            raise RuntimeError(type(self).other_failure)
        if tsig is None or tsig.name not in type(self).accepts:
            try:
                raise dns.tsig.PeerBadKey
            except dns.tsig.PeerBadKey as exc:
                raise RuntimeError(
                    f"AXFR of {zone_name} from {server.host}:53 failed: "
                    "The peer didn't know the key we used."
                ) from exc
        return []


@pytest.fixture
def predates_view_keys() -> Any:
    _PredatesViewKeysDriver.seen = []
    _PredatesViewKeysDriver.accepts = set()
    _PredatesViewKeysDriver.other_failure = None
    register_driver("bind9", _PredatesViewKeysDriver)  # type: ignore[arg-type]
    yield _PredatesViewKeysDriver
    from app.drivers.dns.bind9 import BIND9Driver

    register_driver("bind9", BIND9Driver)


async def test_an_agent_that_predates_view_keys_is_still_read_with_the_group_key(
    db_session: AsyncSession, predates_view_keys: Any
) -> None:
    """Mixed versions (a rolling upgrade, an agent on a host of its own) must
    not lose the read they had: BADKEY on the view key falls back to the
    group key, and the report says the copy may be another view's."""
    predates_view_keys.accepts = {_LEGACY.name}
    grp, _internal, lab = await _views_group(db_session)
    zone = await _zone_with_server(db_session, grp, "bind9")
    zone.view_id = lab.id
    await db_session.flush()

    report = await compute_zone_drift(db_session, group_id=grp.id, zone=zone)

    assert [k.name for k in predates_view_keys.seen] == [
        view_transfer_key(_LEGACY, "lab").name,
        _LEGACY.name,
    ]
    (entry,) = report.servers
    assert entry.status == "ok"
    assert len(report.warnings) == 1
    assert entry.server_name in report.warnings[0]
    assert "could not be addressed to that view" in report.warnings[0]


async def test_badkey_on_every_key_says_what_it_means_under_views(
    db_session: AsyncSession, predates_view_keys: Any
) -> None:
    """The seed shape before the fix: no view admits the transfer, so BIND
    answers BADKEY to every key. The generic hint blames the key; under
    views the message has to name the view and point at the agent's config."""
    grp, internal, _lab = await _views_group(db_session)
    zone = await _zone_with_server(db_session, grp, "bind9")
    zone.view_id = internal.id
    await db_session.flush()

    report = await compute_zone_drift(db_session, group_id=grp.id, zone=zone)

    (entry,) = report.servers
    assert entry.status == "error"
    assert entry.error is not None
    assert "didn't know the key" in entry.error
    assert "'internal'" in entry.error
    assert "applied its current configuration" in entry.error
    assert len(predates_view_keys.seen) == 2


async def test_a_failure_other_than_badkey_is_not_retried(
    db_session: AsyncSession, predates_view_keys: Any
) -> None:
    """Another key cannot fix an unreachable server; retrying only doubles
    the timeout the report waits out."""
    predates_view_keys.other_failure = "AXFR of example.com. failed: timed out."
    grp, _internal, lab = await _views_group(db_session)
    zone = await _zone_with_server(db_session, grp, "bind9")
    zone.view_id = lab.id
    await db_session.flush()

    report = await compute_zone_drift(db_session, group_id=grp.id, zone=zone)

    assert [s.status for s in report.servers] == ["error"]
    assert predates_view_keys.seen == [view_transfer_key(_LEGACY, "lab")]


async def test_sync_with_servers_reads_through_the_zones_view(
    db_session: AsyncSession, recording_driver: type[_RecordingDriver]
) -> None:
    """The other reader of the live zone (#734's second half) gets the same
    addressing — an import from the wrong view's copy would write another
    view's records into this zone."""
    grp, _internal, lab = await _views_group(db_session)
    zone = await _zone_with_server(db_session, grp, "bind9")
    zone.view_id = lab.id
    await db_session.flush()

    await pull_zone_from_server(db_session, zone, apply=False)

    assert recording_driver.seen == [view_transfer_key(_LEGACY, "lab")]
