"""Rolling-upgrade preflight — Kea HA version skew (#637).

Kea 3.0's HA hook is wire-incompatible with peers older than 2.7, so an HA pair
cannot be upgraded node-at-a-time. ``check_kea_ha_version_skew`` surfaces that to
the operator before they press Start.

The tests that matter here are the *scoping* ones. The check is only useful if it
fires for exactly the servers this upgrade will touch, and for exactly the groups
that really are in HA:

* Docker / k8s DHCP agents are never cordoned, drained or slot-swapped by the
  orchestrator — they upgrade through the manual copy-paste path. Counting them
  would let two unrelated containers veto an appliance-cluster upgrade.
* HA is not "≥ 2 Kea members". ``_resolve_failover`` renders the HA hook only
  when every member ALSO has a non-empty ``ha_peer_url``. Without one there is no
  HA relationship and nothing for an upgrade to disrupt.

And the check must never return ``fail``: that sets ``can_start=False``, which
would strand an already-broken pair in its broken state — finishing the upgrade
is precisely what converges both members onto one version.
"""

from __future__ import annotations

import uuid

from sqlalchemy.ext.asyncio import AsyncSession

from app.models.appliance import APPLIANCE_STATE_APPROVED, Appliance
from app.models.dhcp import DHCPServer, DHCPServerGroup
from app.services.upgrades.preflight import check_kea_ha_version_skew


async def _group(
    db: AsyncSession,
    members: list[tuple[str | None, str, str]],
) -> str:
    """Create a group whose members are (kea_version, deployment_kind, ha_peer_url)."""
    name = f"grp-{uuid.uuid4().hex[:8]}"
    g = DHCPServerGroup(name=name)
    db.add(g)
    await db.flush()
    for kea_version, deployment_kind, peer_url in members:
        db.add(
            DHCPServer(
                name=f"kea-{uuid.uuid4().hex[:6]}",
                driver="kea",
                host="127.0.0.1",
                port=67,
                server_group_id=g.id,
                kea_version=kea_version,
                deployment_kind=deployment_kind,
                ha_peer_url=peer_url,
            )
        )
    await db.commit()
    return name


_URL = "http://peer:8000/"


async def test_docker_pair_is_ignored(db_session: AsyncSession) -> None:
    """The orchestrator never touches docker agents. A mixed-version docker pair
    must not veto an appliance upgrade — the original bug set can_start=False."""
    name = await _group(db_session, [("2.6.5", "docker", _URL), ("3.0.3", "docker", _URL)])
    r = await check_kea_ha_version_skew()
    assert r.level == "ok"
    assert name not in r.detail.get("mixed_major", [])


async def test_k8s_pair_is_ignored(db_session: AsyncSession) -> None:
    await _group(db_session, [("2.6.5", "kubernetes", _URL), ("2.6.5", "kubernetes", _URL)])
    r = await check_kea_ha_version_skew()
    assert r.level == "ok"


async def test_unreported_deployment_kind_is_ignored(db_session: AsyncSession) -> None:
    """deployment_kind NULL = hasn't checked in. Strict 'appliance' match only —
    an 'appliance OR NULL' fallback would lie about a row we know nothing about."""
    await _group(db_session, [("2.6.5", None, _URL), ("2.6.5", None, _URL)])
    r = await check_kea_ha_version_skew()
    assert r.level == "ok"


async def test_two_kea_members_without_peer_url_are_not_an_ha_pair(
    db_session: AsyncSession,
) -> None:
    """The core scoping bug: ≥2 Kea members is only HALF of _resolve_failover's
    predicate. With no ha_peer_url the HA hook is never rendered, so there is no
    pair to disrupt — flagging one would block an upgrade over nothing."""
    await _group(db_session, [("2.6.5", "appliance", ""), ("3.0.3", "appliance", "")])
    r = await check_kea_ha_version_skew()
    assert r.level == "ok"


async def test_partial_peer_url_is_not_an_ha_pair(db_session: AsyncSession) -> None:
    """_resolve_failover requires EVERY member to have a URL, not just one."""
    await _group(db_session, [("2.6.5", "appliance", _URL), ("2.6.5", "appliance", "")])
    r = await check_kea_ha_version_skew()
    assert r.level == "ok"


async def test_single_appliance_member_is_not_an_ha_pair(db_session: AsyncSession) -> None:
    await _group(db_session, [("2.6.5", "appliance", _URL)])
    r = await check_kea_ha_version_skew()
    assert r.level == "ok"


async def test_pre_3_appliance_pair_warns(db_session: AsyncSession) -> None:
    name = await _group(db_session, [("2.6.5", "appliance", _URL), ("2.6.5", "appliance", _URL)])
    r = await check_kea_ha_version_skew()
    assert r.level == "warn"
    assert name in r.detail["pre_3_0"]


async def test_mixed_major_warns_but_never_fails(db_session: AsyncSession) -> None:
    """An already-mixed pair has broken HA right now — but blocking the upgrade
    (fail → can_start=False) would strand it there. Completing the run is what
    converges both members, so this must be a warn."""
    name = await _group(db_session, [("2.6.5", "appliance", _URL), ("3.0.3", "appliance", _URL)])
    r = await check_kea_ha_version_skew()
    assert r.level == "warn"
    assert r.level != "fail"
    assert name in r.detail["mixed_major"]


async def test_all_on_3_is_ok(db_session: AsyncSession) -> None:
    """Self-clearing: once every member is on 3.x the check goes quiet, so it is
    not a permanent nag on every future upgrade."""
    await _group(db_session, [("3.0.3", "appliance", _URL), ("3.0.3", "appliance", _URL)])
    r = await check_kea_ha_version_skew()
    assert r.level == "ok"


async def test_unknown_and_pre_3_are_mutually_exclusive(db_session: AsyncSession) -> None:
    """A group with one silent member and one pre-3.0 member must appear under
    exactly ONE heading — the original code appended it to both, so the detail a
    UI renders contradicted itself."""
    name = await _group(db_session, [("2.6.5", "appliance", _URL), (None, "appliance", _URL)])
    r = await check_kea_ha_version_skew()
    assert r.level == "warn"
    headings = [
        h for h in ("mixed_major", "pre_3_0", "unknown_version") if name in r.detail.get(h, [])
    ]
    assert headings == ["unknown_version"], headings


# ── #2179: recognising an appliance node ─────────────────────────────────────
#
# Everything above stamps ``deployment_kind`` on the server row, which no DHCP
# agent has sent since #170 Wave C1 — the kind lives on the supervisor's
# ``appliance`` row. On a real appliance the server row carries NULL and is
# claimed only by the appliance FK or by the agent's host matching the
# appliance's hostname. Before #2179 the check filtered on the column alone and
# answered "No Kea HA pairs" on every appliance cluster.


async def _appliance(
    db: AsyncSession,
    *,
    state: str = APPLIANCE_STATE_APPROVED,
    deployment_kind: str | None = "appliance",
) -> Appliance:
    a = Appliance(
        hostname=f"DDI-{uuid.uuid4().hex[:8]}",
        public_key_der=b"x",
        public_key_fingerprint=uuid.uuid4().hex,
        state=state,
        deployment_kind=deployment_kind,
        assigned_roles=["dhcp"],
    )
    db.add(a)
    await db.flush()
    return a


async def _real_group(
    db: AsyncSession,
    members: list[tuple[str | None, Appliance | None, str, str]],
) -> tuple[str, list[str]]:
    """Members are (kea_version, appliance, link, ha_peer_url) where link is
    ``host`` (agent host = appliance hostname, as register writes it), ``fk``
    (appliance_id set) or ``none`` (a docker agent: no appliance at all).
    ``deployment_kind`` is left NULL on every row, as a real agent leaves it."""
    name = f"grp-{uuid.uuid4().hex[:8]}"
    g = DHCPServerGroup(name=name)
    db.add(g)
    await db.flush()
    servers = []
    for kea_version, appliance, link, peer_url in members:
        sname = f"kea-{uuid.uuid4().hex[:6]}"
        servers.append(sname)
        host = "10.0.0.9"
        appliance_id = None
        if link == "host":
            assert appliance is not None
            # Spelled differently from the appliance row on purpose: the match
            # is the normalised hostname, as ownership.norm_host defines it.
            host = appliance.hostname.lower() + "."
        elif link == "fk":
            assert appliance is not None
            appliance_id = appliance.id
        db.add(
            DHCPServer(
                name=sname,
                driver="kea",
                host=host,
                port=67,
                server_group_id=g.id,
                kea_version=kea_version,
                ha_peer_url=peer_url,
                agent_id=uuid.uuid4(),
                appliance_id=appliance_id,
            )
        )
    await db.commit()
    return name, servers


async def test_appliance_pair_matched_by_hostname_skewed_warns(db_session: AsyncSession) -> None:
    """THE regression test for #2179: an HA pair on two appliances, server rows
    carrying no deployment_kind, members on different Kea majors."""
    a1, a2 = await _appliance(db_session), await _appliance(db_session)
    name, _ = await _real_group(
        db_session, [("2.6.5", a1, "host", _URL), ("3.0.3", a2, "host", _URL)]
    )
    r = await check_kea_ha_version_skew()
    assert r.level == "warn"
    assert r.detail["mixed_major"] == [name]
    assert r.detail["off_appliance_members"] == []


async def test_appliance_pair_matched_by_fk_skewed_warns(db_session: AsyncSession) -> None:
    a1, a2 = await _appliance(db_session), await _appliance(db_session)
    name, _ = await _real_group(db_session, [("2.6.5", a1, "fk", _URL), ("3.0.3", a2, "fk", _URL)])
    r = await check_kea_ha_version_skew()
    assert r.level == "warn"
    assert r.detail["mixed_major"] == [name]


async def test_appliance_pair_on_pre_3_warns(db_session: AsyncSession) -> None:
    a1, a2 = await _appliance(db_session), await _appliance(db_session)
    name, _ = await _real_group(
        db_session, [("2.6.5", a1, "host", _URL), ("2.6.5", a2, "host", _URL)]
    )
    r = await check_kea_ha_version_skew()
    assert r.level == "warn"
    assert r.detail["pre_3_0"] == [name]


async def test_unskewed_appliance_pair_is_seen_and_passes(db_session: AsyncSession) -> None:
    """Same-major pair passes — but it must be SEEN: before #2179 this was
    ``ok`` too, with ``ha_groups: 0``, for the wrong reason."""
    a1, a2 = await _appliance(db_session), await _appliance(db_session)
    await _real_group(db_session, [("3.0.3", a1, "host", _URL), ("3.0.3", a2, "host", _URL)])
    r = await check_kea_ha_version_skew()
    assert r.level == "ok"
    assert r.detail["ha_groups"] == 1


async def test_compose_pair_is_not_checked(db_session: AsyncSession) -> None:
    """A pair with no appliance member is never slot-swapped by this run, so a
    skew there is not this upgrade's business (it is still broken HA — but the
    manual path upgrades it, not the orchestrator)."""
    await _real_group(db_session, [("2.6.5", None, "none", _URL), ("3.0.3", None, "none", _URL)])
    r = await check_kea_ha_version_skew()
    assert r.level == "ok"
    assert r.detail["ha_groups"] == 0


async def test_pair_with_a_docker_partner_names_it(db_session: AsyncSession) -> None:
    """One appliance member, one docker member: a real HA pair (the renderer
    counts every Kea member) that this run splits — and cannot converge, since
    it never touches the docker side. Report it and name the outsider."""
    a1 = await _appliance(db_session)
    name, servers = await _real_group(
        db_session, [("2.6.5", a1, "host", _URL), ("2.6.5", None, "none", _URL)]
    )
    r = await check_kea_ha_version_skew()
    assert r.level == "warn"
    assert r.detail["pre_3_0"] == [name]
    assert r.detail["off_appliance_members"] == [servers[1]]
    assert servers[1] in r.message


async def test_url_less_third_member_suppresses_ha(db_session: AsyncSession) -> None:
    """The HA predicate is evaluated over every Kea member, as _resolve_failover
    does: a third member with no peer URL means no HA hook is rendered, even
    though both appliance members have one."""
    a1, a2 = await _appliance(db_session), await _appliance(db_session)
    await _real_group(
        db_session,
        [("2.6.5", a1, "host", _URL), ("3.0.3", a2, "host", _URL), ("3.0.3", None, "none", "")],
    )
    r = await check_kea_ha_version_skew()
    assert r.level == "ok"


async def test_pending_appliance_does_not_claim_by_hostname(db_session: AsyncSession) -> None:
    a1 = await _appliance(db_session, state="pending_approval")
    a2 = await _appliance(db_session, state="pending_approval")
    await _real_group(db_session, [("2.6.5", a1, "host", _URL), ("3.0.3", a2, "host", _URL)])
    r = await check_kea_ha_version_skew()
    assert r.level == "ok"


async def test_docker_supervisor_does_not_claim(db_session: AsyncSession) -> None:
    """A supervisor on a docker host is an appliance ROW but not a node the
    orchestrator slot-swaps — the strictness the old column match was after."""
    a1 = await _appliance(db_session, deployment_kind="docker")
    a2 = await _appliance(db_session, deployment_kind="docker")
    await _real_group(db_session, [("2.6.5", a1, "host", _URL), ("3.0.3", a2, "host", _URL)])
    r = await check_kea_ha_version_skew()
    assert r.level == "ok"


async def test_off_appliance_note_names_only_the_reported_groups(db_session: AsyncSession) -> None:
    """The message names the mixed-major group only (it returns first); the
    docker member of a separate unknown-version group must not be appended to
    it, or it reads as a member of the mixed pair."""
    a1 = await _appliance(db_session)
    a2 = await _appliance(db_session)
    a3 = await _appliance(db_session)
    mixed, _ = await _real_group(
        db_session, [("2.6.5", a1, "host", _URL), ("3.0.3", a2, "host", _URL)]
    )
    unknown, servers = await _real_group(
        db_session, [(None, a3, "host", _URL), ("3.0.3", None, "none", _URL)]
    )
    r = await check_kea_ha_version_skew()
    assert r.level == "warn"
    assert r.detail["mixed_major"] == [mixed]
    assert r.detail["unknown_version"] == [unknown]
    # Still in the detail, which lists every affected group's outsiders …
    assert r.detail["off_appliance_members"] == [servers[1]]
    # … but not in a message about a different group.
    assert servers[1] not in r.message
