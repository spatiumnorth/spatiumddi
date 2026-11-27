"""Every path that creates a zone refuses a name that is not a domain name."""

from __future__ import annotations

import uuid

import pytest
from pydantic import ValidationError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dns_names import zone_name_storage_error
from app.models.dns import DNSServerGroup, DNSZone
from app.services.ai.operations import CreateDNSZoneArgs

BAD = ['x"; };zone "y', "a b.example.", "../../x.example.", "a{b}.example.", "a;b.example."]


@pytest.mark.parametrize("bad", BAD)
def test_copilot_create_zone_args_refuse_bad_name(bad: str) -> None:
    with pytest.raises(ValidationError):
        CreateDNSZoneArgs(name=bad)


def test_copilot_create_zone_args_normalise_name() -> None:
    assert CreateDNSZoneArgs(name="Example.COM").name == "example.com."


@pytest.mark.parametrize("bad", BAD)
@pytest.mark.asyncio
async def test_zone_row_refuses_bad_name(db_session: AsyncSession, bad: str) -> None:
    g = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}", description="")
    db_session.add(g)
    await db_session.flush()
    with pytest.raises(ValueError):
        DNSZone(group_id=g.id, name=bad, zone_type="primary", kind="forward")


@pytest.mark.parametrize(
    "ok", ["example.com.", "_msdcs.example.com.", "0/26.2.0.192.in-addr.arpa.", "xn--bcher-kva.ch."]
)
def test_legal_names_pass_storage_check(ok: str) -> None:
    assert zone_name_storage_error(ok) is None


def test_copilot_mac_args_use_the_rest_canonical_form() -> None:
    from app.services.ai.operations import AllowlistMacArgs, BlockMacArgs

    assert AllowlistMacArgs(mac_address="AA-BB-CC-DD-EE-FF").mac_address == "aa:bb:cc:dd:ee:ff"
    assert BlockMacArgs(mac_address="aabb.ccdd.eeff").mac_address == "aa:bb:cc:dd:ee:ff"
    with pytest.raises(ValidationError):
        AllowlistMacArgs(mac_address="not-a-mac")
    with pytest.raises(ValidationError):
        BlockMacArgs(mac_address="zz")
