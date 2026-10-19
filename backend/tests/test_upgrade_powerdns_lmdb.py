"""Rolling-upgrade preflight — PowerDNS LMDB one-way schema migration (#638).

PowerDNS 5.0 migrates the LMDB schema v5 → v6 on first open, silently and with
no downgrade. The appliance A/B rollback swaps the rootfs but ``/var`` — where
the database lives — is the shared persistent partition, so rolling a node back
does NOT undo the migration; it leaves the older pdns crash-looping on a
database it cannot read. ``check_powerdns_lmdb_migration`` tells the operator
that before they press Start.

The tests that matter are the scoping ones — the check is only useful if it
fires for exactly the nodes this upgrade will slot-swap:

* An appliance node must be RECOGNISED as one. ``dns_server.deployment_kind``
  looks like the obvious predicate and is a trap: #170 Wave C1 moved that
  telemetry onto the supervisor's heartbeat, so the DNS agent stopped sending
  it and the column is NULL on every post-#170 appliance. A check filtered on
  it alone matches nothing and reports "no PowerDNS nodes" for the exact fleet
  it exists to warn about, which is worse than not shipping it. Hence
  ``test_appliance_matched_by_hostname``.
* Docker / k8s PowerDNS agents upgrade through the manual path and are never
  touched by the orchestrator. Counting them would make an unrelated container
  turn every appliance upgrade amber.
* BIND9 nodes keep zone data as text on disk; there is no equivalent hazard.

And it must never return ``fail``: the migration is a supported, data-preserving
upgrade with an automatic snapshot behind it. The operator needs to be informed,
not blocked.
"""

from __future__ import annotations

import uuid

import pytest
from pydantic import ValidationError
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.dns.agents import AgentHeartbeatRequest
from app.models.appliance import APPLIANCE_STATE_APPROVED, Appliance
from app.models.dns import DNSServer, DNSServerGroup
from app.services.upgrades.preflight import check_powerdns_lmdb_migration


async def _servers(
    db: AsyncSession,
    members: list[tuple[str, str | None, str | None]],
    *,
    host: str = "127.0.0.1",
    agent: bool = False,
) -> list[str]:
    """Create servers described by (driver, daemon_version, deployment_kind)."""
    g = DNSServerGroup(name=f"grp-{uuid.uuid4().hex[:8]}")
    db.add(g)
    await db.flush()
    names = []
    for driver, daemon_version, deployment_kind in members:
        name = f"{driver}-{uuid.uuid4().hex[:6]}"
        names.append(name)
        db.add(
            DNSServer(
                name=name,
                driver=driver,
                host=host,
                port=53,
                group_id=g.id,
                daemon_version=daemon_version,
                deployment_kind=deployment_kind,
                agent_id=uuid.uuid4() if agent else None,
            )
        )
    await db.commit()
    return names


async def test_no_powerdns_nodes_is_ok(db_session: AsyncSession) -> None:
    await _servers(db_session, [("bind9", "9.20.26", "appliance")])
    r = await check_powerdns_lmdb_migration()
    assert r.level == "ok"
    assert r.detail["powerdns_nodes"] == 0


async def test_docker_powerdns_is_ignored(db_session: AsyncSession) -> None:
    """The orchestrator never slot-swaps a docker agent, so a 4.9 container must
    not make an appliance-cluster upgrade look hazardous."""
    await _servers(db_session, [("powerdns", "4.9.5", "docker")])
    r = await check_powerdns_lmdb_migration()
    assert r.level == "ok"
    assert r.detail["powerdns_nodes"] == 0


async def test_kubernetes_powerdns_is_ignored(db_session: AsyncSession) -> None:
    await _servers(db_session, [("powerdns", "4.9.5", "kubernetes")])
    r = await check_powerdns_lmdb_migration()
    assert r.level == "ok"


async def test_unlinked_node_is_ignored(db_session: AsyncSession) -> None:
    """A row with no appliance link at all — no FK, no deployment_kind, and a
    host that matches no appliance — is not something this upgrade touches."""
    await _servers(db_session, [("powerdns", "4.9.5", None)])
    r = await check_powerdns_lmdb_migration()
    assert r.level == "ok"


async def test_appliance_matched_by_hostname(db_session: AsyncSession) -> None:
    """THE regression test for the scoping bug this check shipped with.

    On a real post-#170 appliance the DNS agent sends no ``deployment_kind``
    and nothing writes ``dns_server.appliance_id``, so both direct signals are
    NULL and only the host match identifies the node. Filtering on
    ``deployment_kind = 'appliance'`` alone made the check silently inert on
    every deployment shape it was written for.
    """
    hostname = f"ddi-{uuid.uuid4().hex[:8]}"
    db_session.add(
        Appliance(
            hostname=hostname,
            public_key_der=b"x",
            public_key_fingerprint=uuid.uuid4().hex,
            state=APPLIANCE_STATE_APPROVED,
            deployment_kind="appliance",
        )
    )
    await db_session.flush()
    names = await _servers(db_session, [("powerdns", "4.9.5", None)], host=hostname, agent=True)
    r = await check_powerdns_lmdb_migration()
    assert r.level == "warn"
    assert r.detail["pre_5_0"] == names


async def test_unapproved_appliance_hostname_does_not_claim(db_session: AsyncSession) -> None:
    """#2179 shares the Kea check's membership rule: only an APPROVED appliance
    the orchestrator will slot-swap claims a row by hostname. A pending entry
    (a stale duplicate, a re-paired box) is never rolled by this run."""
    hostname = f"ddi-{uuid.uuid4().hex[:8]}"
    db_session.add(
        Appliance(
            hostname=hostname,
            public_key_der=b"x",
            public_key_fingerprint=uuid.uuid4().hex,
            deployment_kind="appliance",
        )
    )
    await db_session.flush()
    await _servers(db_session, [("powerdns", "4.9.5", None)], host=hostname, agent=True)
    r = await check_powerdns_lmdb_migration()
    assert r.level == "ok"


async def test_pre_5_appliance_node_warns(db_session: AsyncSession) -> None:
    names = await _servers(db_session, [("powerdns", "4.9.5", "appliance")])
    r = await check_powerdns_lmdb_migration()
    assert r.level == "warn"
    assert r.detail["pre_5_0"] == names
    assert not r.detail["unknown_version"]
    # The operator's actual recovery step has to be in the message, not just
    # implied — "roll back the node" is the wrong instruction on its own.
    assert "spatium-pdns-lmdb-guard restore latest" in r.message


async def test_unreported_version_warns_as_unknown(db_session: AsyncSession) -> None:
    """NULL is UNKNOWN, never "old" — but it still warrants the warning, because
    an unreported node could be on 4.x and the migration is irreversible."""
    names = await _servers(db_session, [("powerdns", None, "appliance")])
    r = await check_powerdns_lmdb_migration()
    assert r.level == "warn"
    assert r.detail["unknown_version"] == names
    assert not r.detail["pre_5_0"]


async def test_unparseable_version_counts_as_unknown(db_session: AsyncSession) -> None:
    names = await _servers(db_session, [("powerdns", "not-a-version", "appliance")])
    r = await check_powerdns_lmdb_migration()
    assert r.level == "warn"
    assert r.detail["unknown_version"] == names
    assert not r.detail["pre_5_0"]


async def test_already_on_5_is_ok(db_session: AsyncSession) -> None:
    """Once every node has crossed, the migration has already happened and the
    warning must stop firing — otherwise it becomes noise the operator learns
    to click past."""
    await _servers(db_session, [("powerdns", "5.0.5", "appliance")])
    r = await check_powerdns_lmdb_migration()
    assert r.level == "ok"
    assert r.detail["powerdns_nodes"] == 1


async def test_mixed_fleet_warns_and_lists_only_the_stragglers(
    db_session: AsyncSession,
) -> None:
    old, _new = await _servers(
        db_session,
        [("powerdns", "4.9.5", "appliance"), ("powerdns", "5.0.5", "appliance")],
    )
    r = await check_powerdns_lmdb_migration()
    assert r.level == "warn"
    assert r.detail["pre_5_0"] == [old]
    assert r.detail["powerdns_nodes"] == 2


async def test_never_fails(db_session: AsyncSession) -> None:
    """``fail`` sets can_start=False. Blocking would be wrong: the migration is
    supported and data-preserving, and the agent snapshots before it runs."""
    await _servers(
        db_session,
        [("powerdns", "4.9.5", "appliance"), ("powerdns", None, "appliance")],
    )
    r = await check_powerdns_lmdb_migration()
    assert r.level != "fail"


def test_heartbeat_schema_accepts_daemon_version() -> None:
    """``AgentHeartbeatRequest`` is ``extra="forbid"``, so a field the agent
    sends but the model doesn't declare 422s EVERY heartbeat from a current
    agent — the failure mode is total, not partial."""
    body = AgentHeartbeatRequest.model_validate(
        {"agent_version": "1.2.3", "daemon_version": "5.0.5"}
    )
    assert body.daemon_version == "5.0.5"


def test_heartbeat_schema_still_forbids_unknown_fields() -> None:
    """Guard the guard: adding a field must not have loosened the model."""
    with pytest.raises(ValidationError):
        AgentHeartbeatRequest.model_validate({"pdns_version": "5.0.5"})


def test_heartbeat_schema_daemon_version_optional() -> None:
    """A pre-#638 agent doesn't send the field at all and must keep working."""
    assert AgentHeartbeatRequest.model_validate({}).daemon_version is None


async def _approved(db: AsyncSession, hostname: str, **kw: object) -> Appliance:
    a = Appliance(
        hostname=hostname,
        public_key_der=b"x",
        public_key_fingerprint=uuid.uuid4().hex,
        state=kw.pop("state", APPLIANCE_STATE_APPROVED),
        deployment_kind="appliance",
        **kw,
    )
    db.add(a)
    await db.flush()
    return a


async def test_repaired_box_still_claimed_beside_its_revoked_row(db_session: AsyncSession) -> None:
    """A re-paired appliance leaves its old row behind, revoked, under the same
    hostname. Unlike the move/Fleet ownership rule, the preflight asks "is this
    on SOME node the run touches", so the duplicate must not disable the match —
    the approved twin still claims the row (#2179 narrowed the rule to approved
    appliances; this pins that the narrowing does not lose a real node)."""
    hostname = f"ddi-{uuid.uuid4().hex[:8]}"
    await _approved(db_session, hostname, state="revoked")
    await _approved(db_session, hostname.upper())
    names = await _servers(db_session, [("powerdns", "4.9.5", None)], host=hostname, agent=True)
    r = await check_powerdns_lmdb_migration()
    assert r.level == "warn"
    assert r.detail["pre_5_0"] == names


async def test_appliance_mid_upgrade_still_claims(db_session: AsyncSession) -> None:
    """The upgrade never moves an appliance out of ``approved`` — it records
    progress in ``last_upgrade_state`` — so a node mid-roll (or one whose last
    apply failed) is still a node this run touches. Pinned because the Plan is
    re-read while a run is in flight."""
    hostname = f"ddi-{uuid.uuid4().hex[:8]}"
    await _approved(db_session, hostname, last_upgrade_state="in-progress")
    other = f"ddi-{uuid.uuid4().hex[:8]}"
    await _approved(db_session, other, last_upgrade_state="failed")
    a = await _servers(db_session, [("powerdns", "4.9.5", None)], host=hostname, agent=True)
    b = await _servers(db_session, [("powerdns", "4.9.5", None)], host=other, agent=True)
    r = await check_powerdns_lmdb_migration()
    assert r.level == "warn"
    assert sorted(r.detail["pre_5_0"]) == sorted(a + b)
