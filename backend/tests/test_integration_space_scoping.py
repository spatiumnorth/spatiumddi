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
    EVIDENCE_OPERATOR_CREATE,
    EVIDENCE_OUTSIDE_TARGET_SPACE,
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
async def test_owned_row_in_another_space_is_neither_moved_nor_deleted(
    db_session: AsyncSession, kind: str
) -> None:
    """A row carrying the target's FK but sitting in another space — what a
    pre-#2577 build left behind, or a target whose space was changed. The
    reconciler must not move it into its space, dedupe it away, or
    absence-delete it; repairing it is the operator's call."""
    fk, run = _CASES[kind]
    target, corp_subnet, _ = await _setup(db_session, kind)
    stray = IPAddress(
        subnet_id=corp_subnet.id,
        address=_ADDR,
        status="allocated",
        hostname="corp-host",
        **{fk: target.id},
    )
    db_session.add(stray)
    await db_session.commit()
    before = _snapshot(stray)

    # Still desired: a move would have re-parented it into ``mirror``.
    summary = await run(db_session, target, [_ADDR])
    await db_session.commit()
    assert any("outside its IP space" in w for w in summary.warnings), summary.warnings
    row = await db_session.get(IPAddress, stray.id, populate_existing=True)
    assert row is not None and _snapshot(row) == before, f"{kind} moved or rewrote it"

    # No longer desired: absence-delete would have deleted it.
    await run(db_session, target, [])
    await db_session.commit()
    row = await db_session.get(IPAddress, stray.id, populate_existing=True)
    assert row is not None and _snapshot(row) == before, f"{kind} deleted or released it"


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

    # The damage: an operator-created row now in ``mirror`` carrying the FK.
    stolen = IPAddress(
        subnet_id=mirror_subnet.id,
        address=_ADDR,
        status="allocated",
        hostname="corp-host",
        unifi_controller_id=controller.id,
        user_modified_at=datetime.now(UTC),
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
    assert hit.likely_cross_space
    assert EVIDENCE_OPERATOR_CREATE in hit.evidence
    assert hit.created_by == "alice"
    assert [(h.subnet_id, h.address_free) for h in hit.home_candidates] == [(corp_subnet.id, True)]


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
