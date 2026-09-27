"""One list of integration ownership FKs, used by every guard (#1135).

Each integration mirror stamps its own provenance FK on the IPAM rows it owns
and must not claim a row another integration owns. Seven reconcilers used to
spell that check out by hand, and every copy had fallen behind as integrations
were added. A mirror that misses another's FK claims the row and stamps
``user_modified_at``, which freezes it for both integrations and keeps it
alive after both let go. Block move had the same drift and checked four of
the FKs.

The first two tests keep the list complete and the only copy; the rest pin
the behaviour the drift broke.
"""

from __future__ import annotations

import ast
import uuid
from pathlib import Path
from types import SimpleNamespace

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.ipam import IPAddress, IPBlock, IPSpace, Subnet
from app.models.opnsense import OPNsenseRouter
from app.models.unifi import UnifiController
from app.services.integration_ownership import (
    INTEGRATION_OWNERSHIP,
    INTEGRATION_OWNERSHIP_FKS,
    owned_by_other_integration,
    owning_integration,
)

_APP = Path(__file__).resolve().parents[1] / "app"

# ON DELETE CASCADE FKs that are structure, not ownership: a row goes with
# its parent. Every other CASCADE FK on these tables is an integration's
# provenance column, and deleting that integration's target deletes the row.
_STRUCTURAL_PARENTS = {"subnet_id", "block_id", "parent_block_id", "space_id"}


@pytest.mark.parametrize("model", [IPAddress, Subnet, IPBlock], ids=lambda m: m.__name__)
def test_the_shared_list_is_every_integration_fk_on_the_model(model: type) -> None:
    """A new integration's FK fails here until it is added to
    ``INTEGRATION_OWNERSHIP``, instead of silently narrowing every guard."""
    cascade = {
        column.name
        for column in model.__table__.columns
        if any(fk.ondelete == "CASCADE" for fk in column.foreign_keys)
    }
    assert cascade - _STRUCTURAL_PARENTS == INTEGRATION_OWNERSHIP_FKS


def _is_ownership_attr(node: ast.AST) -> bool:
    """An ownership FK read off an IPAM row or model. ``FirewallObject``
    shares three of the column names, but which of its three firewall
    vendors owns an object is a different question from IPAM ownership."""
    return (
        isinstance(node, ast.Attribute)
        and node.attr in INTEGRATION_OWNERSHIP_FKS
        and not (isinstance(node.value, ast.Name) and node.value.id == "FirewallObject")
    )


def _hand_written_lists(tree: ast.AST) -> list[tuple[int, str]]:
    """Every construct in ``tree`` that names two or more ownership FKs: a
    boolean chain or an ``or_()`` / ``and_()`` over the attributes, a
    literal collection of the column names, or SQL text that names them."""
    found = []
    for node in ast.walk(tree):
        if isinstance(node, ast.BoolOp) or (
            isinstance(node, ast.Call) and getattr(node.func, "id", None) in {"or_", "and_"}
        ):
            names = {n.attr for n in ast.walk(node) if _is_ownership_attr(n)}
            if len(names) >= 2:
                found.append((node.lineno, "a hand-written chain"))
        elif isinstance(node, (ast.Tuple, ast.List, ast.Set, ast.Dict)):
            elts = node.keys if isinstance(node, ast.Dict) else node.elts
            names = {
                e.value
                for e in elts
                if isinstance(e, ast.Constant) and e.value in INTEGRATION_OWNERSHIP_FKS
            }
            if len(names) >= 2:
                found.append((node.lineno, "a private copy of the list"))
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            text = node.value
            if "NULL" in text.upper() and sum(fk in text for fk in INTEGRATION_OWNERSHIP_FKS) >= 2:
                found.append((node.lineno, "SQL naming the columns"))
    return found


def test_no_guard_spells_out_the_list() -> None:
    """Every guard goes through ``app.services.integration_ownership``, so a
    new copy can't drift again. ``app/models`` is out of scope: it defines
    the columns, and ``FirewallObject.source_id`` picks between its own three
    vendors, which is not an ownership guard."""
    home = _APP / "services" / "integration_ownership.py"
    offenders = []
    for path in sorted(_APP.rglob("*.py")):
        if path == home or (_APP / "models") in path.parents:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        offenders += [
            f"{path.relative_to(_APP.parent)}:{line}: {what}"
            for line, what in _hand_written_lists(tree)
        ]
    assert not offenders, "use app.services.integration_ownership instead of:\n" + "\n".join(
        offenders
    )


def _row(**owners: object) -> SimpleNamespace:
    return SimpleNamespace(**{fk: owners.get(fk) for fk in INTEGRATION_OWNERSHIP})


def test_the_helpers() -> None:
    opnsense_owned = _row(opnsense_router_id=uuid.uuid4())
    assert owning_integration(opnsense_owned) == "opnsense"
    assert owned_by_other_integration(opnsense_owned, "unifi_controller_id")
    assert not owned_by_other_integration(opnsense_owned, "opnsense_router_id")
    assert owning_integration(_row()) is None
    assert not owned_by_other_integration(_row(), "unifi_controller_id")
    with pytest.raises(ValueError):
        owned_by_other_integration(_row(), "subnet_id")


# ── The cross-claim the drift allowed ─────────────────────────────────────


async def _space(db: AsyncSession) -> IPSpace:
    space = IPSpace(name=f"own-{uuid.uuid4().hex[:6]}", description="")
    db.add(space)
    await db.flush()
    return space


async def _opnsense(db: AsyncSession, space: IPSpace) -> OPNsenseRouter:
    router = OPNsenseRouter(
        name=f"fw-{uuid.uuid4().hex[:6]}",
        host="fw.example.test",
        api_key="KEY",
        api_secret_encrypted=b"",
        ipam_space_id=space.id,
    )
    db.add(router)
    await db.flush()
    return router


async def _unifi(db: AsyncSession, space: IPSpace) -> UnifiController:
    controller = UnifiController(name=f"unifi-{uuid.uuid4().hex[:6]}", ipam_space_id=space.id)
    db.add(controller)
    await db.flush()
    return controller


async def _subnet(db: AsyncSession, space: IPSpace, cidr: str, **owners: object) -> Subnet:
    block = IPBlock(space_id=space.id, network=cidr, name=f"b-{cidr}")
    db.add(block)
    await db.flush()
    subnet = Subnet(
        space_id=space.id,
        block_id=block.id,
        network=cidr,
        name=f"s-{cidr}",
        total_ips=254,
        **owners,
    )
    db.add(subnet)
    await db.flush()
    return subnet


async def test_unifi_does_not_claim_an_opnsense_row(db_session: AsyncSession) -> None:
    """The issue's UniFi ← OPNsense case, the common homelab pairing: one host
    is both a UniFi client and an OPNsense DHCP lease. UniFi's guard lacked
    ``opnsense_router_id``, so it adopted the row and stamped
    ``user_modified_at``, after which neither integration updated it."""
    from app.services.unifi.reconcile import (  # noqa: PLC0415
        ReconcileSummary,
        _apply_addresses,
        _DesiredAddress,
    )

    space = await _space(db_session)
    router = await _opnsense(db_session, space)
    controller = await _unifi(db_session, space)
    subnet = await _subnet(db_session, space, "192.168.1.0/24")
    row = IPAddress(
        subnet_id=subnet.id,
        address="192.168.1.50",
        status="dhcp",
        hostname="nas",
        opnsense_router_id=router.id,
    )
    db_session.add(row)
    await db_session.commit()

    summary = ReconcileSummary(ok=True)
    await _apply_addresses(
        db_session,
        controller,
        [
            _DesiredAddress(
                address="192.168.1.50",
                status="unifi-client",
                hostname="nas",
                description="",
                mac="aa:bb:cc:dd:ee:ff",
                network_id=None,
            )
        ],
        summary,
    )
    await db_session.refresh(row)
    assert row.unifi_controller_id is None
    assert row.opnsense_router_id == router.id
    assert row.user_modified_at is None, "a cross-claim freezes the row for both integrations"
    assert any("owned by another integration" in w for w in summary.warnings), summary.warnings


async def test_block_move_is_refused_for_every_integration(db_session: AsyncSession) -> None:
    """Block move checked four integrations, so a block holding rows owned by
    any of the others moved, and that integration's reconciler re-created
    them in the source space on its next sync."""
    from app.services.ipam.block_move import assemble_move_plan  # noqa: PLC0415

    source = await _space(db_session)
    target = await _space(db_session)
    router = await _opnsense(db_session, source)
    controller = await _unifi(db_session, source)
    block = IPBlock(space_id=source.id, network="10.77.0.0/16", name="moving")
    db_session.add(block)
    await db_session.flush()
    subnet = Subnet(
        space_id=source.id,
        block_id=block.id,
        network="10.77.1.0/24",
        name="fw-lan",
        total_ips=254,
        opnsense_router_id=router.id,
    )
    db_session.add(subnet)
    await db_session.flush()
    db_session.add(
        IPAddress(
            subnet_id=subnet.id,
            address="10.77.1.20",
            status="unifi-client",
            unifi_controller_id=controller.id,
        )
    )
    await db_session.commit()

    plan = await assemble_move_plan(db_session, block, target.id, None)
    blockers = {(b.kind, b.integration) for b in plan.integration_blockers}
    assert ("subnet", "opnsense") in blockers
    assert ("ip_address", "unifi") in blockers
