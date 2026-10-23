"""Integration mirrors stay inside their own IP space (#2577).

IP spaces are independent: the same address in two spaces is two hosts.
Seven reconcilers looked existing ``IPAddress`` rows up by bare address
across every space, adopted the operator's row, moved it into the
integration's space and could then delete it. OPNsense alone had been fixed.

The behavioural tests run every reconciler's address phase against two
spaces holding the same address. The structural test fails any reconciler
query that loads ``IPAddress`` rows without a space or subnet bound, so a
new reconciler cannot bring the bug back. The last block covers the
read-only detector for damage an earlier build already did.
"""

from __future__ import annotations

import ast
import dataclasses
import importlib
import uuid
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.audit import AuditLog
from app.models.auth import User
from app.models.cloud import CloudEndpoint
from app.models.docker import DockerHost
from app.models.ipam import IPAddress, IPBlock, IPSpace, Subnet
from app.models.kubernetes import KubernetesCluster
from app.models.netbird import NetbirdInstance
from app.models.opnsense import OPNsenseRouter
from app.models.panos import PANOSFirewall
from app.models.proxmox import ProxmoxNode
from app.models.tailscale import TailscaleTenant
from app.models.unifi import UnifiController
from app.services.integration_ownership import INTEGRATION_OWNERSHIP_FKS
from app.services.ipam.integration_space_audit import (
    EVIDENCE_DHCP_RESERVATION_OTHER_SPACE,
    EVIDENCE_OPERATOR_CREATE,
    EVIDENCE_OUTSIDE_TARGET_SPACE,
    EVIDENCE_PREDATES_SPACE_SUBNETS,
    TARGET_MODELS,
    find_cross_space_adoptions,
)

_APP = Path(__file__).resolve().parents[1] / "app"
_ADDR = "10.250.0.10"
_CIDR = "10.250.0.0/24"


def _n(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:6]}"


# ── Per-reconciler plumbing ───────────────────────────────────────────────


def _desired(cls: type, address: str) -> Any:
    """Build a reconciler's desired-address dataclass from whichever of the
    common fields it declares."""
    values: dict[str, Any] = {
        "address": address,
        "status": "reserved",
        "hostname": "mirror-host",
        "description": "from the integration",
        "mac": None,
        "network_id": None,
        "custom_fields": {},
    }
    names = {f.name for f in dataclasses.fields(cls)}
    return cls(**{k: v for k, v in values.items() if k in names})


def _module_runner(module: str) -> Callable[..., Awaitable[Any]]:
    """Run ``<module>._apply_addresses`` for ``target`` with ``addresses``."""
    mod = importlib.import_module(module)

    async def run(db: AsyncSession, target: Any, addresses: list[str]) -> Any:
        summary = mod.ReconcileSummary(ok=True)
        desired = [_desired(mod._DesiredAddress, a) for a in addresses]
        await mod._apply_addresses(db, target, desired, summary)
        return summary

    return run


async def _run_firewall(db: AsyncSession, target: Any, addresses: list[str]) -> Any:
    from app.services.firewall_mirror import (  # noqa: PLC0415
        PALOALTO_OWNER,
        MirrorAddress,
        MirrorSummary,
        apply_addresses,
    )

    summary = MirrorSummary()
    await apply_addresses(
        db,
        PALOALTO_OWNER,
        target.id,
        target.ipam_space_id,
        [
            MirrorAddress(address=a, mac=None, hostname="mirror-host", description="")
            for a in addresses
        ],
        summary,
    )
    return summary


def _targets(space_id: uuid.UUID) -> dict[str, Any]:
    return {
        "unifi": UnifiController(name=_n("unifi"), ipam_space_id=space_id),
        "docker": DockerHost(
            name=_n("docker"),
            connection_type="tcp",
            endpoint=f"{_n('d')}.example.test:2376",
            ipam_space_id=space_id,
            client_key_encrypted=b"",
        ),
        "kubernetes": KubernetesCluster(
            name=_n("k8s"),
            api_server_url="https://k8s.example.test:6443",
            ca_bundle_pem="",
            token_encrypted=b"x",
            ipam_space_id=space_id,
            pod_cidr="",
            service_cidr="",
        ),
        "proxmox": ProxmoxNode(
            name=_n("pve"),
            host=f"{_n('h')}.example.test",
            token_id="root@pam!t",
            token_secret_encrypted=b"",
            ipam_space_id=space_id,
        ),
        "tailscale": TailscaleTenant(
            name=_n("ts"), tailnet="-", api_key_encrypted=b"", ipam_space_id=space_id
        ),
        "netbird": NetbirdInstance(name=_n("nb"), ipam_space_id=space_id),
        "cloud": CloudEndpoint(
            name=_n("cloud"),
            provider="aws",
            credentials_encrypted=b"",
            provider_config={},
            regions=["us-east-1"],
            ipam_space_id=space_id,
        ),
        "opnsense": OPNsenseRouter(
            name=_n("fw"),
            host="fw.example.test",
            api_key="KEY",
            api_secret_encrypted=b"",
            ipam_space_id=space_id,
        ),
        "paloalto": PANOSFirewall(
            name=_n("pa"),
            host="pa.example.test",
            api_key_encrypted=b"",
            ipam_space_id=space_id,
        ),
    }


_CASES: dict[str, tuple[str, Callable[..., Awaitable[Any]]]] = {
    "unifi": ("unifi_controller_id", _module_runner("app.services.unifi.reconcile")),
    "docker": ("docker_host_id", _module_runner("app.services.docker.reconcile")),
    "kubernetes": (
        "kubernetes_cluster_id",
        _module_runner("app.services.kubernetes.reconcile"),
    ),
    "proxmox": ("proxmox_node_id", _module_runner("app.services.proxmox.reconcile")),
    "tailscale": ("tailscale_tenant_id", _module_runner("app.services.tailscale.reconcile")),
    "netbird": ("netbird_instance_id", _module_runner("app.services.netbird.reconcile")),
    "cloud": ("cloud_endpoint_id", _module_runner("app.services.cloud.reconcile")),
    "opnsense": ("opnsense_router_id", _module_runner("app.services.opnsense.reconcile")),
    "paloalto": ("panos_firewall_id", _run_firewall),
}


async def _space(db: AsyncSession, name: str) -> IPSpace:
    space = IPSpace(name=_n(name), description="")
    db.add(space)
    await db.flush()
    return space


async def _subnet(db: AsyncSession, space: IPSpace, cidr: str = _CIDR, **kw: Any) -> Subnet:
    block = IPBlock(space_id=space.id, network=cidr, name=_n("b"))
    db.add(block)
    await db.flush()
    subnet = Subnet(
        space_id=space.id, block_id=block.id, network=cidr, name=_n("s"), total_ips=254, **kw
    )
    db.add(subnet)
    await db.flush()
    return subnet


async def _setup(db: AsyncSession, kind: str) -> tuple[Any, Subnet, Subnet]:
    """Space ``corp`` (operator) and space ``mirror`` (the integration's),
    both carrying the same /24. The target points at ``mirror``."""
    corp = await _space(db, "corp")
    mirror = await _space(db, "mirror")
    corp_subnet = await _subnet(db, corp)
    fk = _CASES[kind][0]
    # Cloud only mirrors into subnets it owns; the others match any subnet
    # in their space. Ownership of the subnet is not what is under test.
    target = _targets(mirror.id)[kind]
    db.add(target)
    await db.flush()
    mirror_subnet = await _subnet(db, mirror, **({fk: target.id} if kind == "cloud" else {}))
    return target, corp_subnet, mirror_subnet


def _snapshot(row: IPAddress) -> dict[str, Any]:
    return {
        "subnet_id": row.subnet_id,
        "user_modified_at": row.user_modified_at,
        "hostname": row.hostname,
        "status": row.status,
        "owners": {fk: getattr(row, fk) for fk in INTEGRATION_OWNERSHIP_FKS},
    }


@pytest.mark.parametrize("kind", list(_CASES))
async def test_operator_row_in_another_space_is_never_adopted(
    db_session: AsyncSession, kind: str
) -> None:
    """The reported scenario: an operator row in ``corp`` at an address the
    integration (pointed at ``mirror``) also sees. It must stay exactly as it
    was, and the integration gets its own row in its own space."""
    fk, run = _CASES[kind]
    target, corp_subnet, mirror_subnet = await _setup(db_session, kind)
    operator = IPAddress(
        subnet_id=corp_subnet.id, address=_ADDR, status="allocated", hostname="corp-host"
    )
    db_session.add(operator)
    await db_session.commit()
    before = _snapshot(operator)

    await run(db_session, target, [_ADDR])
    await db_session.commit()

    row = await db_session.get(IPAddress, operator.id, populate_existing=True)
    assert row is not None, f"{kind} deleted an operator row in another space"
    assert _snapshot(row) == before, f"{kind} changed an operator row in another space"

    ours = (
        (await db_session.execute(select(IPAddress).where(getattr(IPAddress, fk) == target.id)))
        .scalars()
        .all()
    )
    assert [(r.subnet_id, str(r.address)) for r in ours] == [(mirror_subnet.id, _ADDR)]


@pytest.mark.parametrize("kind", list(_CASES))
async def test_pure_mirror_row_left_in_another_space_is_deleted_not_moved(
    db_session: AsyncSession, kind: str
) -> None:
    """A row the target created and nobody touched, sitting in another space —
    what changing the target's ``ipam_space_id`` leaves behind. It is released
    by deleting it (the integration re-creates its row in its own space); it is
    never moved across spaces."""
    fk, run = _CASES[kind]
    target, corp_subnet, mirror_subnet = await _setup(db_session, kind)
    stray = IPAddress(
        subnet_id=corp_subnet.id,
        address=_ADDR,
        status="allocated",
        hostname="mirror-host",
        **{fk: target.id},
    )
    db_session.add(stray)
    await db_session.commit()
    stray_id = stray.id

    summary = await run(db_session, target, [_ADDR])
    await db_session.commit()
    assert any(
        "released what this target owned outside" in w for w in summary.warnings
    ), summary.warnings
    assert await db_session.get(IPAddress, stray_id, populate_existing=True) is None
    ours = (
        (await db_session.execute(select(IPAddress).where(getattr(IPAddress, fk) == target.id)))
        .scalars()
        .all()
    )
    assert [(r.subnet_id, str(r.address)) for r in ours] == [(mirror_subnet.id, _ADDR)]


@pytest.mark.parametrize("kind", list(_CASES))
async def test_adopted_row_in_another_space_is_unclaimed_in_place(
    db_session: AsyncSession, kind: str
) -> None:
    """An operator row carrying the target's FK in its HOME space — adopted by
    a pre-#2577 build that never moved it, or adopted before a space change.
    It is un-claimed in place: FK cleared, same subnet, ``user_modified_at``
    kept. Never moved, never deleted — whether still desired or not."""
    fk, run = _CASES[kind]
    target, corp_subnet, _ = await _setup(db_session, kind)
    stamp = datetime.now(UTC) - timedelta(days=3)
    stray = IPAddress(
        subnet_id=corp_subnet.id,
        address=_ADDR,
        status="allocated",
        hostname="corp-host",
        user_modified_at=stamp,
        **{fk: target.id},
    )
    db_session.add(stray)
    await db_session.commit()

    summary = await run(db_session, target, [_ADDR])
    await db_session.commit()
    assert any("1 un-claimed" in w for w in summary.warnings), summary.warnings
    row = await db_session.get(IPAddress, stray.id, populate_existing=True)
    assert row is not None, f"{kind} deleted an adopted operator row"
    assert row.subnet_id == corp_subnet.id
    assert row.user_modified_at == stamp
    assert row.hostname == "corp-host"
    assert all(getattr(row, f) is None for f in INTEGRATION_OWNERSHIP_FKS)


async def _evidence_created_by(db: AsyncSession, row: IPAddress, target: Any) -> None:
    user = User(
        username=_n("u"),
        email=f"{_n('u')}@example.com",
        display_name="u",
        hashed_password=hash_password("password123"),
        auth_source="local",
    )
    user.groups = []
    db.add(user)
    await db.flush()
    row.created_by_user_id = user.id


async def _evidence_audit(db: AsyncSession, row: IPAddress, target: Any) -> None:
    await _audit_create(db, row)


async def _evidence_older(db: AsyncSession, row: IPAddress, target: Any) -> None:
    await db.refresh(target, ["created_at"])
    row.created_at = target.created_at - timedelta(days=30)


async def _evidence_other_owner(db: AsyncSession, row: IPAddress, target: Any) -> None:
    other = _targets(uuid.uuid4())["unifi"]
    other.ipam_space_id = target.ipam_space_id
    db.add(other)
    await db.flush()
    row.unifi_controller_id = other.id


@pytest.mark.parametrize(
    "evidence",
    [_evidence_created_by, _evidence_audit, _evidence_older, _evidence_other_owner],
    ids=["created_by_user", "operator_audit", "older_than_target", "second_owner"],
)
async def test_unclear_rows_outside_the_space_are_unclaimed_never_deleted(
    db_session: AsyncSession, evidence: Callable[..., Awaitable[None]]
) -> None:
    """``user_modified_at`` is not the only sign of a person's hand. A row with
    any other one — or a second owner — is un-claimed, not deleted: when the
    evidence is unclear the release fails towards keeping the row."""
    fk, run = _CASES["docker"]
    target, corp_subnet, _ = await _setup(db_session, "docker")
    stray = IPAddress(
        subnet_id=corp_subnet.id, address=_ADDR, status="allocated", **{fk: target.id}
    )
    db_session.add(stray)
    await db_session.flush()
    await evidence(db_session, stray, target)
    await db_session.commit()

    await run(db_session, target, [])
    await db_session.commit()
    row = await db_session.get(IPAddress, stray.id, populate_existing=True)
    assert row is not None
    assert row.subnet_id == corp_subnet.id
    assert row.docker_host_id is None


@pytest.mark.parametrize("kind", list(_CASES))
async def test_pre_fix_damage_inside_the_target_space_is_not_released(
    db_session: AsyncSession, kind: str
) -> None:
    """An operator row a pre-#2577 build already MOVED into the target's space
    is not "outside" — the release must not delete or un-claim it; the audit
    report and the operator decide."""
    fk, run = _CASES[kind]
    target, _, mirror_subnet = await _setup(db_session, kind)
    stolen = IPAddress(
        subnet_id=mirror_subnet.id,
        address=_ADDR,
        status="allocated",
        hostname="corp-host",
        user_modified_at=datetime.now(UTC),
        **{fk: target.id},
    )
    db_session.add(stolen)
    await db_session.flush()
    await _audit_create(db_session, stolen)
    await db_session.commit()

    summary = await run(db_session, target, [_ADDR])
    await db_session.commit()
    assert not any("released" in w for w in summary.warnings), summary.warnings
    row = await db_session.get(IPAddress, stolen.id, populate_existing=True)
    assert row is not None
    assert row.subnet_id == mirror_subnet.id
    assert getattr(row, fk) == target.id


async def test_same_space_adoption_still_works(db_session: AsyncSession) -> None:
    """The documented behaviour scoping must not break: an operator row in the
    integration's OWN space is adopted and locked."""
    fk, run = _CASES["docker"]
    target, _, mirror_subnet = await _setup(db_session, "docker")
    operator = IPAddress(subnet_id=mirror_subnet.id, address=_ADDR, status="allocated")
    db_session.add(operator)
    await db_session.commit()

    await run(db_session, target, [_ADDR])
    await db_session.commit()
    row = await db_session.get(IPAddress, operator.id, populate_existing=True)
    assert row is not None
    assert getattr(row, fk) == target.id
    assert row.user_modified_at is not None


# ── Space re-targeting: owned subnets (#2577) ─────────────────────────────


def _subnet_desired(kind: str, network: str) -> Any:
    mod = importlib.import_module(f"app.services.{kind}.reconcile")
    values: dict[str, Any] = {
        "network": network,
        "name": f"{kind}-net",
        "description": "mirror",
        "gateway": None,
        "site_name": "default",
        "network_id": "n1",
        "vlan_tag": None,
        "vlan_name": "",
    }
    names = {f.name for f in dataclasses.fields(mod._DesiredSubnet)}
    return mod._DesiredSubnet(**{k: v for k, v in values.items() if k in names})


async def _run_subnet_phase(db: AsyncSession, kind: str, target: Any, networks: list[str]) -> Any:
    mod = importlib.import_module(f"app.services.{kind}.reconcile")
    summary = mod.ReconcileSummary(ok=True)
    desired = [_subnet_desired(kind, n) for n in networks]
    if kind == "unifi":
        await mod._apply_blocks_and_subnets(db, target, desired, {}, summary)
    else:
        await mod._apply_blocks_and_subnets(db, target, desired, summary)
    return summary


_SUBNET_KINDS = ["docker", "unifi", "kubernetes"]


@pytest.mark.parametrize("kind", _SUBNET_KINDS)
async def test_space_change_releases_the_old_space_and_rebuilds_in_the_new(
    db_session: AsyncSession, kind: str
) -> None:
    """Re-target an integration from space ``old`` to ``new``. Its pure mirror
    subnet and rows in ``old`` are deleted, an operator row it adopted there is
    un-claimed in place (and keeps its subnet alive, un-claimed), and the next
    pass builds the mirror in ``new``. Nothing moves between spaces."""
    fk, run = _CASES[kind]
    old = await _space(db_session, "old")
    new = await _space(db_session, "new")
    target = _targets(old.id)[kind]
    db_session.add(target)
    await db_session.flush()

    await _run_subnet_phase(db_session, kind, target, [_CIDR, "10.251.0.0/24"])
    await run(db_session, target, [_ADDR, "10.251.0.7"])
    await db_session.commit()
    old_subnets = {
        str(s.network): s
        for s in (
            await db_session.execute(select(Subnet).where(Subnet.space_id == old.id))
        ).scalars()
    }
    assert getattr(old_subnets[_CIDR], fk) == target.id
    # The operator adopts-in-place an address in the second subnet.
    adopted = IPAddress(
        subnet_id=old_subnets["10.251.0.0/24"].id,
        address="10.251.0.20",
        status="allocated",
        hostname="kept",
        user_modified_at=datetime.now(UTC),
        **{fk: target.id},
    )
    db_session.add(adopted)
    await db_session.commit()
    kept_subnet_id = old_subnets["10.251.0.0/24"].id
    gone_subnet_id = old_subnets[_CIDR].id
    old_id, new_id, adopted_id, target_id = old.id, new.id, adopted.id, target.id

    target.ipam_space_id = new.id
    await db_session.commit()
    summary = await _run_subnet_phase(db_session, kind, target, [_CIDR, "10.251.0.0/24"])
    await run(db_session, target, [_ADDR, "10.251.0.7"])
    await db_session.commit()
    assert any("released what this target owned outside" in w for w in summary.warnings)

    db_session.expire_all()
    assert await db_session.get(Subnet, gone_subnet_id) is None
    kept = await db_session.get(Subnet, kept_subnet_id)
    assert kept is not None and kept.space_id == old_id
    assert getattr(kept, fk) is None
    row = await db_session.get(IPAddress, adopted_id)
    assert row is not None and row.subnet_id == kept_subnet_id and getattr(row, fk) is None
    assert row.user_modified_at is not None
    leftovers = (
        await db_session.execute(
            select(IPAddress)
            .join(Subnet, IPAddress.subnet_id == Subnet.id)
            .where(Subnet.space_id == old_id, getattr(IPAddress, fk) == target_id)
        )
    ).all()
    assert leftovers == []

    ours = (
        await db_session.execute(
            select(Subnet.network, Subnet.space_id).where(getattr(Subnet, fk) == target_id)
        )
    ).all()
    assert {(str(n), sp) for n, sp in ours} == {(_CIDR, new_id), ("10.251.0.0/24", new_id)}
    addrs = (
        await db_session.execute(
            select(IPAddress.address, Subnet.space_id)
            .join(Subnet, IPAddress.subnet_id == Subnet.id)
            .where(getattr(IPAddress, fk) == target_id)
        )
    ).all()
    assert {(str(a), sp) for a, sp in addrs} == {(_ADDR, new_id), ("10.251.0.7", new_id)}


@pytest.mark.parametrize("kind", _SUBNET_KINDS)
async def test_owned_subnet_in_another_space_is_never_updated_or_reparented(
    db_session: AsyncSession, kind: str
) -> None:
    """Before the fix the subnet phase loaded the target's subnets from every
    space, renamed them and re-parented them under a block of the NEW space.
    A subnet an operator has a row in is un-claimed and left exactly as it
    was."""
    fk, _ = _CASES[kind]
    old = await _space(db_session, "old")
    new = await _space(db_session, "new")
    target = _targets(new.id)[kind]
    db_session.add(target)
    await db_session.flush()
    subnet = await _subnet(db_session, old, **{fk: target.id})
    subnet.name = "operator-name"
    db_session.add(IPAddress(subnet_id=subnet.id, address=_ADDR, status="allocated"))
    await db_session.commit()
    block_id, subnet_id, old_id = subnet.block_id, subnet.id, old.id

    await _run_subnet_phase(db_session, kind, target, [_CIDR])
    await db_session.commit()
    db_session.expire_all()
    row = await db_session.get(Subnet, subnet_id)
    assert row is not None
    assert (row.space_id, row.block_id, row.name) == (old_id, block_id, "operator-name")
    assert getattr(row, fk) is None


async def test_release_helper_ignores_an_empty_space_list(db_session: AsyncSession) -> None:
    """ "No space" is never read as "everything is outside"."""
    from app.services.integration_ownership import release_outside_space

    fk, _ = _CASES["docker"]
    target, corp_subnet, _ = await _setup(db_session, "docker")
    stray = IPAddress(
        subnet_id=corp_subnet.id, address=_ADDR, status="allocated", **{fk: target.id}
    )
    db_session.add(stray)
    await db_session.commit()
    out = await release_outside_space(db_session, fk, target.id, [None])
    assert out.total == 0
    assert (await db_session.get(IPAddress, stray.id, populate_existing=True)) is not None


# ── Structural guard ──────────────────────────────────────────────────────


def _reconciler_files() -> list[Path]:
    return sorted(_APP.glob("services/*/reconcile.py")) + [_APP / "services/firewall_mirror.py"]


def _unscoped_address_selects(tree: ast.AST, source: str) -> list[tuple[int, str]]:
    """Every ``select(IPAddress…)`` whose statement filters on an address or
    an ownership FK without bounding it to a subnet or space. Such a query
    reaches rows in every IP space."""
    parents: dict[ast.AST, ast.AST] = {}
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            parents[child] = node

    def names_ipaddress(arg: ast.AST) -> bool:
        return (isinstance(arg, ast.Name) and arg.id == "IPAddress") or (
            isinstance(arg, ast.Attribute)
            and isinstance(arg.value, ast.Name)
            and arg.value.id == "IPAddress"
        )

    found = []
    for node in ast.walk(tree):
        if not (
            isinstance(node, ast.Call)
            and getattr(node.func, "id", None) == "select"
            and any(names_ipaddress(a) for a in node.args)
        ):
            continue
        top: ast.AST = node
        while True:
            parent = parents.get(top)
            if isinstance(parent, ast.Attribute) and parent.value is top:
                top = parent
            elif isinstance(parent, ast.Call) and parent.func is top:
                top = parent
            else:
                break
        text = ast.get_source_segment(source, top) or ""
        filters_on = (
            "IPAddress.address" in text
            or any(f"IPAddress.{fk}" in text for fk in INTEGRATION_OWNERSHIP_FKS)
            or "getattr(IPAddress" in text
        )
        bounded = "IPAddress.subnet_id" in text or "Subnet.space_id" in text
        if filters_on and not bounded:
            found.append((node.lineno, text.splitlines()[0]))
    return found


def test_no_reconciler_loads_addresses_across_spaces() -> None:
    """Load ``IPAddress`` rows through ``addresses_in_space`` /
    ``owned_addresses_in_space``, or bound the query by subnet or space."""
    offenders = []
    for path in _reconciler_files():
        source = path.read_text()
        for line, text in _unscoped_address_selects(ast.parse(source), source):
            offenders.append(f"{path.relative_to(_APP)}:{line}: {text.strip()}")
    assert not offenders, "unscoped IPAddress lookups (#2577):\n" + "\n".join(offenders)


def _unscoped_owned_selects(tree: ast.AST, source: str) -> list[tuple[int, str]]:
    """Every ``select(Subnet…)`` / ``select(IPBlock…)`` filtered by an
    integration ownership FK without a ``space_id`` bound. Ownership alone
    reaches the target's rows in every space — its old space after a space
    change — which the subnet phase then renamed, re-parented under a block
    of the new space, or deleted with what it held."""
    parents: dict[ast.AST, ast.AST] = {}
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            parents[child] = node
    found = []
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and getattr(node.func, "id", None) == "select"):
            continue
        model = next(
            (a.id for a in node.args if isinstance(a, ast.Name) and a.id in ("Subnet", "IPBlock")),
            None,
        )
        if model is None:
            continue
        top: ast.AST = node
        while True:
            parent = parents.get(top)
            if isinstance(parent, ast.Attribute) and parent.value is top:
                top = parent
            elif isinstance(parent, ast.Call) and parent.func is top:
                top = parent
            else:
                break
        text = ast.get_source_segment(source, top) or ""
        by_owner = any(f"{model}.{fk}" in text for fk in INTEGRATION_OWNERSHIP_FKS) or (
            f"getattr({model}" in text
        )
        if by_owner and f"{model}.space_id" not in text:
            found.append((node.lineno, text.splitlines()[0]))
    return found


def test_no_reconciler_loads_owned_subnets_or_blocks_across_spaces() -> None:
    """Load a target's subnets through ``owned_subnets_in_space``, or bound
    the query by ``space_id``."""
    offenders = []
    for path in _reconciler_files():
        source = path.read_text()
        for line, text in _unscoped_owned_selects(ast.parse(source), source):
            offenders.append(f"{path.relative_to(_APP)}:{line}: {text.strip()}")
    assert not offenders, "unscoped owned Subnet/IPBlock lookups (#2577):\n" + "\n".join(offenders)


def test_the_subnet_guard_catches_the_pre_fix_shape() -> None:
    bad = (
        "async def f(db, t, s, c):\n"
        "    a = await db.execute(select(Subnet).where(Subnet.docker_host_id == t))\n"
        "    b = await db.execute(select(IPBlock).where(IPBlock.tailscale_tenant_id == t,\n"
        "        IPBlock.network == c))\n"
        "    ok = await db.execute(select(Subnet).where(Subnet.unifi_controller_id == t,\n"
        "        Subnet.space_id == s))\n"
        "    ok2 = await db.execute(select(Subnet).where(Subnet.space_id == s))\n"
    )
    assert [line for line, _ in _unscoped_owned_selects(ast.parse(bad), bad)] == [2, 3]


def test_every_reconciler_that_moves_rows_guards_the_move() -> None:
    offenders = []
    for path in _reconciler_files():
        source = path.read_text()
        moves = any(
            isinstance(node, ast.Assign)
            and any(isinstance(t, ast.Attribute) and t.attr == "subnet_id" for t in node.targets)
            for node in ast.walk(ast.parse(source))
        )
        if moves and "move_stays_in_space(" not in source:
            offenders.append(str(path.relative_to(_APP)))
    assert not offenders, offenders


def test_the_guard_catches_the_pre_fix_shape() -> None:
    """Negative control for the scanner itself: the exact pre-#2577 queries."""
    bad = (
        "async def f(db, ids, t):\n"
        "    a = await db.execute(select(IPAddress).where(IPAddress.address.in_(ids)))\n"
        "    b = await db.execute(select(IPAddress).where(IPAddress.unifi_controller_id == t))\n"
        "    ok = await db.execute(select(IPAddress.id).where(\n"
        "        IPAddress.subnet_id == t, IPAddress.address == ids))\n"
    )
    assert [line for line, _ in _unscoped_address_selects(ast.parse(bad), bad)] == [2, 3]


def test_detector_covers_every_integration() -> None:
    assert set(TARGET_MODELS) == INTEGRATION_OWNERSHIP_FKS


# ── Damage detection (#2577 item 7) ───────────────────────────────────────


async def _audit_create(db: AsyncSession, ip: IPAddress, who: str = "alice") -> None:
    db.add(
        AuditLog(
            user_id=uuid.uuid4(),
            user_display_name=who,
            auth_source="local",
            action="create",
            resource_type="ip_address",
            resource_id=str(ip.id),
            resource_display=str(ip.address),
            new_value={"address": str(ip.address)},
            result="success",
        )
    )


async def test_detector_reports_a_stolen_row_and_its_home(db_session: AsyncSession) -> None:
    corp = await _space(db_session, "corp")
    mirror = await _space(db_session, "mirror")
    corp_subnet = await _subnet(db_session, corp)
    mirror_subnet = await _subnet(db_session, mirror)
    controller = UnifiController(name=_n("unifi"), ipam_space_id=mirror.id)
    db_session.add(controller)
    await db_session.flush()
    now = datetime.now(UTC)
    # The corp subnet long predates the row; the mirror subnet came later.
    corp_subnet.created_at = now - timedelta(days=60)

    # The damage: an operator-created row now in ``mirror`` carrying the FK.
    stolen = IPAddress(
        subnet_id=mirror_subnet.id,
        address=_ADDR,
        status="allocated",
        hostname="corp-host",
        unifi_controller_id=controller.id,
        user_modified_at=now,
        created_at=now - timedelta(days=30),
    )
    # The integration's own row at an overlapping address: not damage.
    own = IPAddress(
        subnet_id=mirror_subnet.id,
        address="10.250.0.11",
        status="unifi-client",
        unifi_controller_id=controller.id,
    )
    db_session.add_all([stolen, own])
    await db_session.flush()
    await _audit_create(db_session, stolen)
    await db_session.commit()

    rows = await find_cross_space_adoptions(db_session)
    assert [r.ip_address_id for r in rows] == [stolen.id]
    hit = rows[0]
    assert hit.integration == "unifi"
    assert hit.likely_cross_space and not hit.needs_review
    assert EVIDENCE_OPERATOR_CREATE in hit.evidence
    assert EVIDENCE_PREDATES_SPACE_SUBNETS in hit.evidence
    assert hit.created_by == "alice"
    assert [(h.subnet_id, h.address_free) for h in hit.home_candidates] == [(corp_subnet.id, True)]


async def test_same_space_adoption_in_an_overlapping_range_is_not_flagged_as_damage(
    db_session: AsyncSession,
) -> None:
    """An operator row created in the integration's own space, then adopted
    there. The same range existing in another space is no evidence the row
    came from it: listed for review, never ``likely_cross_space``."""
    corp = await _space(db_session, "corp")
    mirror = await _space(db_session, "mirror")
    corp_subnet = await _subnet(db_session, corp)
    mirror_subnet = await _subnet(db_session, mirror)
    now = datetime.now(UTC)
    # Both subnets predate the row: it could have been created in either.
    corp_subnet.created_at = now - timedelta(days=90)
    mirror_subnet.created_at = now - timedelta(days=60)
    host = _targets(mirror.id)["docker"]
    db_session.add(host)
    await db_session.flush()
    adopted = IPAddress(
        subnet_id=mirror_subnet.id,
        address=_ADDR,
        status="allocated",
        docker_host_id=host.id,
        user_modified_at=now,
        created_at=now - timedelta(days=30),
    )
    db_session.add(adopted)
    await db_session.flush()
    await _audit_create(db_session, adopted)
    await db_session.commit()

    rows = await find_cross_space_adoptions(db_session)
    assert [r.ip_address_id for r in rows] == [adopted.id]
    assert not rows[0].likely_cross_space
    assert rows[0].needs_review and rows[0].review_reason
    assert EVIDENCE_PREDATES_SPACE_SUBNETS not in rows[0].evidence


async def test_detector_uses_a_dhcp_reservation_in_another_space_as_evidence(
    db_session: AsyncSession,
) -> None:
    from app.models.dhcp import DHCPScope, DHCPServerGroup, DHCPStaticAssignment

    corp = await _space(db_session, "corp")
    mirror = await _space(db_session, "mirror")
    corp_subnet = await _subnet(db_session, corp)
    mirror_subnet = await _subnet(db_session, mirror)
    host = _targets(mirror.id)["docker"]
    db_session.add(host)
    await db_session.flush()
    stolen = IPAddress(
        subnet_id=mirror_subnet.id,
        address=_ADDR,
        status="allocated",
        docker_host_id=host.id,
        user_modified_at=datetime.now(UTC),
    )
    db_session.add(stolen)
    group = DHCPServerGroup(name=_n("g"), description="")
    db_session.add(group)
    await db_session.flush()
    scope = DHCPScope(group_id=group.id, subnet_id=corp_subnet.id, name="corp")
    db_session.add(scope)
    await db_session.flush()
    db_session.add(
        DHCPStaticAssignment(
            scope_id=scope.id,
            ip_address=_ADDR,
            mac_address="aa:bb:cc:00:25:77",
            ip_address_id=stolen.id,
        )
    )
    await db_session.flush()
    await _audit_create(db_session, stolen)
    await db_session.commit()

    rows = await find_cross_space_adoptions(db_session)
    assert [r.ip_address_id for r in rows] == [stolen.id]
    assert rows[0].likely_cross_space
    assert EVIDENCE_DHCP_RESERVATION_OTHER_SPACE in rows[0].evidence


async def test_detector_reports_a_cloud_row_outside_when_there_is_no_public_space(
    db_session: AsyncSession,
) -> None:
    """``public_space_id`` NULL made the target-space test NULL rather than
    false, so a Cloud row in a foreign space was never reported."""
    corp = await _space(db_session, "corp")
    mirror = await _space(db_session, "mirror")
    corp_subnet = await _subnet(db_session, corp)
    endpoint = _targets(mirror.id)["cloud"]
    assert endpoint.public_space_id is None
    db_session.add(endpoint)
    await db_session.flush()
    stray = IPAddress(
        subnet_id=corp_subnet.id, address=_ADDR, status="allocated", cloud_endpoint_id=endpoint.id
    )
    db_session.add(stray)
    await db_session.commit()

    rows = await find_cross_space_adoptions(db_session)
    assert [r.ip_address_id for r in rows] == [stray.id]
    assert EVIDENCE_OUTSIDE_TARGET_SPACE in rows[0].evidence


async def test_detector_truncation_is_honest(db_session: AsyncSession) -> None:
    """The cap applies to real findings. Before, each model's query was capped
    at ``limit * 4`` BEFORE the Python filter, so rows that matched the SQL
    but not the rules could crowd out real findings — and the cut was never
    reported."""
    from app.services.ipam.integration_space_audit import audit_cross_space_adoptions

    corp = await _space(db_session, "corp")
    mirror = await _space(db_session, "mirror")
    corp_subnet = await _subnet(db_session, corp, "10.252.0.0/24")
    mirror_subnet = await _subnet(db_session, mirror, "10.10.0.0/24")
    host = _targets(mirror.id)["docker"]
    db_session.add(host)
    await db_session.flush()
    # Five operator-audited adoptions in the host's own space with no overlap
    # anywhere — not findings — sorting before the one real finding.
    noise = [
        IPAddress(
            subnet_id=mirror_subnet.id,
            address=f"10.10.0.{i}",
            status="allocated",
            docker_host_id=host.id,
            user_modified_at=datetime.now(UTC),
        )
        for i in range(1, 6)
    ]
    real = [
        IPAddress(
            subnet_id=corp_subnet.id,
            address=f"10.252.0.{i}",
            status="allocated",
            docker_host_id=host.id,
        )
        for i in (1, 2)
    ]
    db_session.add_all(noise + real)
    await db_session.flush()
    for row in noise:
        await _audit_create(db_session, row)
    await db_session.commit()

    one = await audit_cross_space_adoptions(db_session, limit=1)
    assert [str(r.address) for r in one.rows] == ["10.252.0.1"]
    assert one.truncated
    both = await audit_cross_space_adoptions(db_session, limit=2)
    assert len(both.rows) == 2 and not both.truncated


async def test_detector_reports_rows_outside_the_target_space(db_session: AsyncSession) -> None:
    corp = await _space(db_session, "corp")
    mirror = await _space(db_session, "mirror")
    corp_subnet = await _subnet(db_session, corp)
    host = _targets(mirror.id)["docker"]
    db_session.add(host)
    await db_session.flush()
    stray = IPAddress(
        subnet_id=corp_subnet.id, address=_ADDR, status="allocated", docker_host_id=host.id
    )
    db_session.add(stray)
    await db_session.commit()

    rows = await find_cross_space_adoptions(db_session)
    assert [r.ip_address_id for r in rows] == [stray.id]
    assert EVIDENCE_OUTSIDE_TARGET_SPACE in rows[0].evidence


async def test_detector_ignores_same_space_adoption_unless_asked(
    db_session: AsyncSession,
) -> None:
    mirror = await _space(db_session, "mirror")
    mirror_subnet = await _subnet(db_session, mirror)
    host = _targets(mirror.id)["docker"]
    db_session.add(host)
    await db_session.flush()
    adopted = IPAddress(
        subnet_id=mirror_subnet.id,
        address=_ADDR,
        status="allocated",
        docker_host_id=host.id,
        user_modified_at=datetime.now(UTC),
        created_at=datetime.now(UTC) - timedelta(days=30),
    )
    db_session.add(adopted)
    await db_session.commit()

    assert await find_cross_space_adoptions(db_session) == []
    rows = await find_cross_space_adoptions(db_session, include_same_space=True)
    assert [r.ip_address_id for r in rows] == [adopted.id]
    assert not rows[0].likely_cross_space


async def test_report_endpoint_is_superadmin_only(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    tokens = {}
    for name, sa in (("root", True), ("viewer", False)):
        user = User(
            username=_n(name),
            email=f"{_n(name)}@example.com",
            display_name=name,
            hashed_password=hash_password("password123"),
            auth_source="local",
            is_superadmin=sa,
        )
        user.groups = []
        db_session.add(user)
        await db_session.flush()
        tokens[name] = create_access_token(str(user.id))
    await db_session.commit()

    url = "/api/v1/ipam/integration-space-audit"
    ok = await client.get(url, headers={"Authorization": f"Bearer {tokens['root']}"})
    assert ok.status_code == 200, ok.text
    assert ok.json() == {"count": 0, "truncated": False, "rows": []}
    denied = await client.get(url, headers={"Authorization": f"Bearer {tokens['viewer']}"})
    assert denied.status_code == 403


# ── A release is reported, and counted (#2577, walk case 3) ───────────────


async def _superadmin_headers(db: AsyncSession) -> dict[str, str]:
    user = User(
        username=_n("root"),
        email=f"{_n('root')}@example.com",
        display_name="root",
        hashed_password=hash_password("password123"),
        auth_source="local",
        is_superadmin=True,
    )
    user.groups = []
    db.add(user)
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


async def _release_rows(db: AsyncSession, resource_type: str, target_id: Any) -> list[AuditLog]:
    from app.services.integration_ownership import RELEASE_AUDIT_ACTION  # noqa: PLC0415

    return list(
        (
            await db.execute(
                select(AuditLog).where(
                    AuditLog.action == RELEASE_AUDIT_ACTION,
                    AuditLog.resource_type == resource_type,
                    AuditLog.resource_id == str(target_id),
                )
            )
        )
        .scalars()
        .all()
    )


@pytest.mark.parametrize("kind", list(_CASES))
async def test_a_release_is_audited_counted_and_listed_on_the_dashboard(
    client: AsyncClient, db_session: AsyncSession, kind: str
) -> None:
    """Re-targeting leaves the target's rows in its old space. The sync that
    releases them must say so: a release audit row with the true counts, the
    sync's own deleted counter and ``released`` total, and the Integrations
    dashboard's warnings list and target row. Before the walk-3 fix only
    OPNsense kept the warning, and every sync reported 0 deleted."""
    from app.services.integration_ownership import (  # noqa: PLC0415
        ownership_resource_type,
    )

    fk, run = _CASES[kind]
    headers = await _superadmin_headers(db_session)
    target, corp_subnet, _ = await _setup(db_session, kind)
    for i in (11, 12):
        db_session.add(
            IPAddress(
                subnet_id=corp_subnet.id,
                address=f"10.250.0.{i}",
                status="allocated",
                **{fk: target.id},
            )
        )
    await db_session.commit()

    summary = await run(db_session, target, [])
    await db_session.commit()

    assert summary.released.addresses_deleted == 2, summary.released
    assert summary.addresses_deleted >= 2, "the sync's own count must include released rows"
    rtype = ownership_resource_type(fk)
    rows = await _release_rows(db_session, rtype, target.id)
    assert len(rows) == 1
    assert rows[0].new_value["released"]["addresses_deleted"] == 2
    assert rows[0].resource_display == target.name
    assert rows[0].user_id is None and rows[0].result == "success"

    r = await client.get("/api/v1/dashboards/integrations/summary", headers=headers)
    assert r.status_code == 200, r.text
    body = r.json()
    listed = [w for w in body["recent_warnings"] if w["target_id"] == str(target.id)]
    assert len(listed) == 1 and listed[0]["integration"] == rtype
    assert "2 address row(s) (2 deleted" in (listed[0]["error_detail"] or "")
    row = next(t for p in body["panels"] for t in p["targets"] if t["id"] == str(target.id))
    assert "released what this target owned outside" in (row["last_sync_warning"] or "")


async def test_a_full_kubernetes_resync_after_a_retarget_reports_the_release(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The walk's case 3, end to end through ``reconcile_cluster``: the sync
    audit row and the summary count the rows and the subnet the re-target
    released, instead of reading 0 deleted."""
    import app.services.kubernetes.reconcile as k8s  # noqa: PLC0415

    class _Client:
        def __init__(self, **_kw: Any) -> None:
            pass

        async def __aenter__(self) -> _Client:
            return self

        async def __aexit__(self, *_a: Any) -> None:
            return None

        async def _empty(self) -> list[Any]:
            return []

        list_nodes = list_services = list_loadbalancer_services = _empty
        list_pods = list_ingresses = _empty

    monkeypatch.setattr(k8s, "KubernetesClient", _Client)
    monkeypatch.setattr(k8s, "decrypt_str", lambda _b: "token")

    old = await _space(db_session, "old")
    new = await _space(db_session, "new")
    cluster = _targets(old.id)["kubernetes"]
    cluster.service_cidr = _CIDR
    db_session.add(cluster)
    await db_session.commit()

    first = await k8s.reconcile_cluster(db_session, cluster)
    assert first.ok, first.error
    old_subnet = (
        await db_session.execute(
            select(Subnet).where(
                Subnet.space_id == old.id, Subnet.kubernetes_cluster_id == cluster.id
            )
        )
    ).scalar_one()
    db_session.add(
        IPAddress(
            subnet_id=old_subnet.id,
            address=_ADDR,
            status="kubernetes-service",
            kubernetes_cluster_id=cluster.id,
        )
    )
    await db_session.commit()

    cluster.ipam_space_id = new.id
    await db_session.commit()
    summary = await k8s.reconcile_cluster(db_session, cluster)
    assert summary.ok, summary.error
    assert summary.released.addresses_deleted == 1
    assert summary.released.subnets_deleted == 1
    assert summary.addresses_deleted >= 1 and summary.subnets_deleted >= 1

    sync_row = (
        (
            await db_session.execute(
                select(AuditLog)
                .where(
                    AuditLog.action == "kubernetes.reconcile",
                    AuditLog.resource_id == str(cluster.id),
                )
                .order_by(AuditLog.timestamp.desc(), AuditLog.id.desc())
            )
        )
        .scalars()
        .first()
    )
    assert sync_row is not None
    value = sync_row.new_value
    assert value["released"]["addresses_deleted"] == 1
    assert value["released"]["subnets_deleted"] == 1
    assert value["addresses"]["deleted"] >= 1 and value["subnets"]["deleted"] >= 1
    assert len(await _release_rows(db_session, "kubernetes_cluster", cluster.id)) == 1


def _sync_task_files() -> list[Path]:
    return [
        p
        for p in sorted(_APP.glob("tasks/*_sync.py"))
        if p.stem.removesuffix("_sync") in {*(k for k in _CASES), "panos", "fortinet", "meraki"}
    ]


def test_every_reconciler_reports_its_release_on_audit_log_and_result() -> None:
    """Each reconciler's sync audit row and log line, and each sync task's
    result, carry ``summary.released`` — a release is never left out of the
    counts the operator reads."""
    files = [
        p for p in sorted(_APP.glob("services/*/reconcile.py")) if '.reconcile",' in p.read_text()
    ]
    assert len(files) == 11, [p.parent.name for p in files]
    missing = []
    for path in files:
        text = path.read_text()
        if '"released": summary.released.as_dict()' not in text:
            missing.append(f"{path.relative_to(_APP)}: sync audit row")
        if "**summary.released.log_fields()" not in text:
            missing.append(f"{path.relative_to(_APP)}: log line")
        if "refuse_sync_into_trashed_space(" not in text:
            missing.append(f"{path.relative_to(_APP)}: trashed-space check")
    tasks = _sync_task_files()
    assert len(tasks) == 11, [p.name for p in tasks]
    for path in tasks:
        if '"released": summary.released.as_dict()' not in path.read_text():
            missing.append(f"{path.relative_to(_APP)}: task result")
    assert missing == []


# ── A target whose IP space is in Trash syncs nothing (#2577) ─────────────


def _trash_cases(space_id: uuid.UUID) -> dict[str, tuple[str, Any]]:
    from app.models.fortinet import FortinetFirewall  # noqa: PLC0415
    from app.models.meraki import MerakiOrg  # noqa: PLC0415

    t = _targets(space_id)
    return {
        "unifi": ("app.services.unifi.reconcile:reconcile_controller", t["unifi"]),
        "docker": ("app.services.docker.reconcile:reconcile_host", t["docker"]),
        "kubernetes": ("app.services.kubernetes.reconcile:reconcile_cluster", t["kubernetes"]),
        "proxmox": ("app.services.proxmox.reconcile:reconcile_node", t["proxmox"]),
        "tailscale": ("app.services.tailscale.reconcile:reconcile_tenant", t["tailscale"]),
        "netbird": ("app.services.netbird.reconcile:reconcile_instance", t["netbird"]),
        "cloud": ("app.services.cloud.reconcile:reconcile_endpoint", t["cloud"]),
        "opnsense": ("app.services.opnsense.reconcile:reconcile_router", t["opnsense"]),
        "paloalto": ("app.services.panos.reconcile:reconcile_firewall", t["paloalto"]),
        "fortinet": (
            "app.services.fortinet.reconcile:reconcile_firewall",
            FortinetFirewall(name=_n("fgt"), host="fgt.example.test", ipam_space_id=space_id),
        ),
        "meraki": (
            "app.services.meraki.reconcile:reconcile_org",
            MerakiOrg(name=_n("meraki"), ipam_space_id=space_id),
        ),
    }


@pytest.mark.parametrize("kind", list(_trash_cases(uuid.uuid4())))
async def test_a_target_whose_space_is_in_trash_writes_nothing(
    db_session: AsyncSession, kind: str
) -> None:
    """The walk's observation: a cluster left enabled after its space was
    trashed kept rebuilding its block and subnets inside the trashed space.
    Every reconciler now stops before it fetches anything, with a sync error
    that says why."""
    from app.services.integration_ownership import SPACE_IN_TRASH_ERROR  # noqa: PLC0415

    space = await _space(db_session, "trashed")
    path, target = _trash_cases(space.id)[kind]
    db_session.add(target)
    await db_session.flush()
    space.deleted_at = datetime.now(UTC)
    await db_session.commit()

    async def ipam_counts() -> tuple[int, int, int]:
        out = []
        for model in (IPBlock, Subnet, IPAddress):
            out.append(
                len(
                    (
                        await db_session.execute(
                            select(model.id).execution_options(include_deleted=True)
                        )
                    ).all()
                )
            )
        return out[0], out[1], out[2]

    before = await ipam_counts()
    module, fn = path.split(":")
    reconcile = getattr(importlib.import_module(module), fn)
    summary = await reconcile(db_session, target)

    assert not summary.ok
    assert summary.error == SPACE_IN_TRASH_ERROR
    await db_session.refresh(target)
    assert target.last_sync_error == SPACE_IN_TRASH_ERROR
    assert target.last_synced_at is not None
    assert await ipam_counts() == before


async def test_a_live_space_is_not_reported_as_trashed(db_session: AsyncSession) -> None:
    from app.services.integration_ownership import target_space_in_trash  # noqa: PLC0415

    live = await _space(db_session, "live")
    trashed = await _space(db_session, "trashed")
    trashed.deleted_at = datetime.now(UTC)
    await db_session.commit()
    assert not await target_space_in_trash(db_session, live.id)
    assert not await target_space_in_trash(db_session, [live.id, None])
    assert await target_space_in_trash(db_session, trashed.id)
    assert await target_space_in_trash(db_session, [live.id, trashed.id])


async def test_deleting_a_target_removes_what_it_owns(db_session: AsyncSession) -> None:
    """Deleting a target cleans its own block, subnet and addresses (the FK
    cascades), live or in a trashed space. Unowned supernet blocks a
    reconciler creates are not its to delete."""
    fk, _ = _CASES["kubernetes"]
    space = await _space(db_session, "k8s")
    cluster = _targets(space.id)["kubernetes"]
    db_session.add(cluster)
    await db_session.flush()
    block = IPBlock(space_id=space.id, network="10.249.0.0/16", name=_n("b"), **{fk: cluster.id})
    db_session.add(block)
    await db_session.flush()
    subnet = Subnet(
        space_id=space.id,
        block_id=block.id,
        network="10.249.1.0/24",
        name=_n("s"),
        total_ips=254,
        **{fk: cluster.id},
    )
    db_session.add(subnet)
    await db_session.flush()
    addr = IPAddress(
        subnet_id=subnet.id, address="10.249.1.5", status="allocated", **{fk: cluster.id}
    )
    db_session.add(addr)
    await db_session.commit()
    ids = (block.id, subnet.id, addr.id)

    await db_session.delete(cluster)
    await db_session.commit()
    db_session.expire_all()
    for model, row_id in zip((IPBlock, Subnet, IPAddress), ids, strict=True):
        row = (
            await db_session.execute(
                select(model).where(model.id == row_id).execution_options(include_deleted=True)
            )
        ).scalar_one_or_none()
        assert row is None, model.__name__
