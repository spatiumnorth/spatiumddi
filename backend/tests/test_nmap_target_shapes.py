"""nmap scan targets: one host, one CIDR, or one real hostname.

nmap reads dotted digit / dash spellings such as ``10.0.0.1-20`` as octet
ranges, so they must not pass as hostnames: they expand to many hosts the
per-subnet checks never see and sidestep the CIDR size cap.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.ipam import IPBlock, IPSpace, Subnet
from app.services.ipam.probe_policy import check_probe_target
from app.services.nmap.runner import NmapArgError, _validate_target


@pytest.mark.parametrize(
    "target",
    [
        "10.0.0.1-20",
        "10.0.0-5.1",
        "10.0-255.0-255.0-255",
        "10.0.0.*",
        "10.0.0.1,2",
        "10.0.0.1-20.",
        "1-5",
    ],
)
def test_range_and_list_spellings_are_refused(target: str) -> None:
    with pytest.raises(NmapArgError):
        _validate_target(target)


@pytest.mark.parametrize(
    ("target", "expected"),
    [
        ("host-1.example.com", "host-1.example.com"),
        ("router1", "router1"),
        ("10.0.0.5", "10.0.0.5"),
        ("10.0.0.0/24", "10.0.0.0/24"),
    ],
)
def test_single_targets_still_accepted(target: str, expected: str) -> None:
    assert _validate_target(target) == expected


def test_cidr_over_the_size_cap_is_still_refused() -> None:
    with pytest.raises(NmapArgError):
        _validate_target("10.0.0.0/8")


async def test_cidr_inside_a_flagged_subnet_is_still_refused(db_session: AsyncSession) -> None:
    space = IPSpace(name=f"s-{uuid.uuid4().hex[:8]}")
    db_session.add(space)
    await db_session.flush()
    block = IPBlock(space_id=space.id, name="b", network="10.77.0.0/16")
    db_session.add(block)
    await db_session.flush()
    subnet = Subnet(
        space_id=space.id,
        block_id=block.id,
        name="s",
        network="10.77.1.0/24",
        do_not_probe=True,
    )
    db_session.add(subnet)
    await db_session.flush()
    verdict = await check_probe_target(db_session, _validate_target("10.77.1.0/28"))
    assert verdict.blocked is True
