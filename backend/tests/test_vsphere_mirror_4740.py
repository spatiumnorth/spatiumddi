"""vSphere mirror (#4740): the real REST client + reconciler against recorded
vSphere Automation API payloads (``tests/fixtures/vsphere``), served through an
``httpx.MockTransport`` so no vCenter is needed."""

from __future__ import annotations

import base64
import json
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from unittest.mock import patch

import httpx
import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.crypto import encrypt_str
from app.models.audit import AuditLog
from app.models.docker import DockerHost
from app.models.ipam import IPAddress, IPBlock, IPSpace, Subnet
from app.models.vsphere import VSphereTarget
from app.services.integration_ownership import SPACE_IN_TRASH_ERROR
from app.services.vsphere import client as vclient
from app.services.vsphere.reconcile import reconcile_target

FIX = Path(__file__).parent / "fixtures" / "vsphere"
_RealAsyncClient = httpx.AsyncClient


def _fx(name: str) -> Any:
    return json.loads((FIX / name).read_text())


class FakeVCenter:
    """Serves the recorded payloads; ``overrides`` swap one path's answer."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []
        self.session_auth: str | None = None
        self.overrides: dict[str, tuple[int, Any]] = {}
        self.vms: Any = _fx("vm_list.json")
        self.client_kwargs: list[dict[str, Any]] = []
        self.guest: dict[str, tuple[int, Any]] = {
            "vm-101": (200, _fx("guest_vm-101.json")),
            "vm-102": (200, _fx("guest_vm-102.json")),
            "vm-104": (200, _fx("guest_vm-104.json")),
        }

    def handler(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        self.calls.append((request.method, path))
        if path in self.overrides:
            code, body = self.overrides[path]
            return httpx.Response(code, json=body)
        if path == "/api/session":
            if request.method == "POST":
                self.session_auth = request.headers.get("authorization")
                return httpx.Response(201, json=_fx("session.json"))
            return httpx.Response(204)
        assert request.headers.get("vmware-api-session-id"), "session header missing"
        if path == "/api/appliance/system/version":
            return httpx.Response(200, json=_fx("version.json"))
        if path == "/api/vcenter/host":
            return httpx.Response(200, json=_fx("host_list.json"))
        if path == "/api/vcenter/vm":
            return httpx.Response(200, json=self.vms)
        if path.startswith("/api/vcenter/vm/") and path.endswith("/guest/networking/interfaces"):
            vm = path.split("/")[4]
            code, body = self.guest.get(vm, (503, _fx("guest_error_tools_not_running.json")))
            return httpx.Response(code, json=body)
        return httpx.Response(404, json={"error_type": "NOT_FOUND"})

    def install(self) -> Callable[..., Any]:
        def factory(**kwargs: Any) -> httpx.AsyncClient:
            self.client_kwargs.append(kwargs)
            return _RealAsyncClient(transport=httpx.MockTransport(self.handler), **kwargs)

        return factory


@pytest.fixture
def vc() -> Any:
    fake = FakeVCenter()
    with patch.object(vclient.httpx, "AsyncClient", fake.install()):
        yield fake


async def _setup(db: AsyncSession, **kw: Any) -> tuple[VSphereTarget, Subnet]:
    space = IPSpace(name=f"vs-{uuid.uuid4().hex[:6]}", description="")
    db.add(space)
    await db.flush()
    block = IPBlock(space_id=space.id, network="10.20.0.0/16", name="b")
    db.add(block)
    await db.flush()
    subnet = Subnet(
        space_id=space.id, block_id=block.id, network="10.20.0.0/16", name="s", total_ips=65534
    )
    db.add(subnet)
    await db.flush()
    target = VSphereTarget(
        name=f"vc-{uuid.uuid4().hex[:6]}",
        host="vc.example.test",
        username="svc@vsphere.local",
        password_encrypted=encrypt_str("s3cret"),
        ipam_space_id=space.id,
        **kw,
    )
    db.add(target)
    await db.flush()
    return target, subnet


async def _rows(db: AsyncSession, target: VSphereTarget) -> dict[str, IPAddress]:
    res = await db.execute(select(IPAddress).where(IPAddress.vsphere_target_id == target.id))
    return {str(a.address): a for a in res.scalars().all()}


@pytest.mark.asyncio
async def test_first_sync_mirrors_guest_ips_and_hosts(db_session: AsyncSession, vc: Any) -> None:
    target, subnet = await _setup(db_session)
    summary = await reconcile_target(db_session, target)
    assert summary.ok, summary.error
    rows = await _rows(db_session, target)
    # vm-101 (one PREFERRED address; the link-local and TENTATIVE ones are
    # noise), vm-102, and the ESXi host named by its IP. vm-104's 172.31.x
    # address has no enclosing subnet; powered-off vm-103 is not mirrored.
    assert sorted(rows) == ["10.20.0.11", "10.20.1.10", "10.20.1.20"]
    web = rows["10.20.1.10"]
    assert (web.status, web.hostname, web.mac_address) == (
        "vsphere-vm",
        "web-01",
        "00:50:56:aa:bb:01",
    )
    assert web.subnet_id == subnet.id and "vm-101" in (web.description or "")
    assert rows["10.20.0.11"].status == "vsphere-host"
    assert summary.skipped_no_subnet == 1
    await db_session.refresh(subnet)
    assert subnet.allocated_ips == 3
    assert target.vcenter_version == "8.0.2" and (target.host_count, target.vm_count) == (2, 4)
    # The session was opened with Basic auth and closed again.
    expected = "Basic " + base64.b64encode(b"svc@vsphere.local:s3cret").decode()
    assert vc.session_auth == expected
    assert vc.calls[-1] == ("DELETE", "/api/session")
    # TLS is verified unless the operator opted out.
    assert vc.client_kwargs[0]["verify"] is True
    audit = (
        await db_session.execute(select(AuditLog).where(AuditLog.action == "vsphere.reconcile"))
    ).scalar_one()
    assert audit.new_value["addresses"]["created"] == 3


@pytest.mark.asyncio
async def test_tls_opt_out_is_explicit(db_session: AsyncSession, vc: Any) -> None:
    target, _ = await _setup(db_session, verify_tls=False)
    await reconcile_target(db_session, target)
    assert vc.client_kwargs[0]["verify"] is False


@pytest.mark.asyncio
async def test_discovery_says_why_a_vm_has_no_address(db_session: AsyncSession, vc: Any) -> None:
    target, _ = await _setup(db_session)
    vc.guest.pop("vm-102")  # VMware Tools not running
    await reconcile_target(db_session, target)
    vms = {v["vm"]: v for v in target.last_discovery["vms"]}
    assert vms["vm-102"]["issue"] == "tools_not_running"
    assert "VMware Tools" in vms["vm-102"]["hint"]
    assert vms["vm-102"]["nic_count"] == 0  # unknown, not "no NICs"
    assert vms["vm-103"]["issue"] == "powered_off"
    assert vms["vm-104"]["issue"] == "no_subnet"
    assert vms["vm-101"]["issue"] is None
    assert target.last_discovery["summary"]["vm_tools_not_running"] == 1


@pytest.mark.asyncio
async def test_tools_not_running_keeps_rows_but_a_gone_vm_is_deleted(
    db_session: AsyncSession, vc: Any
) -> None:
    target, _ = await _setup(db_session)
    await reconcile_target(db_session, target)
    assert "10.20.1.20" in await _rows(db_session, target)

    vc.guest.pop("vm-102")  # VMware Tools stops: unknown, not empty
    s2 = await reconcile_target(db_session, target)
    rows = await _rows(db_session, target)
    assert "10.20.1.20" in rows and s2.held_vms == 1 and s2.addresses_deleted == 0

    vc.vms = [v for v in vc.vms if v["vm"] != "vm-102"]  # the VM is deleted
    s3 = await reconcile_target(db_session, target)
    assert "10.20.1.20" not in await _rows(db_session, target)
    assert s3.addresses_deleted == 1


@pytest.mark.asyncio
async def test_operator_rows_are_claimed_locked_and_released(
    db_session: AsyncSession, vc: Any
) -> None:
    target, subnet = await _setup(db_session)
    mine = IPAddress(
        subnet_id=subnet.id, address="10.20.1.10", status="allocated", hostname="keep-me"
    )
    other = DockerHost(
        name="d",
        connection_type="tcp",
        endpoint="d.example.test:2376",
        ipam_space_id=target.ipam_space_id,
        client_key_encrypted=b"",
    )
    db_session.add_all([mine, other])
    await db_session.flush()
    theirs = IPAddress(
        subnet_id=subnet.id,
        address="10.20.1.20",
        status="docker-container",
        docker_host_id=other.id,
    )
    db_session.add(theirs)
    await db_session.flush()

    s = await reconcile_target(db_session, target)
    await db_session.refresh(mine)
    await db_session.refresh(theirs)
    assert mine.vsphere_target_id == target.id and mine.user_modified_at is not None
    assert mine.hostname == "keep-me" and mine.status == "allocated"  # locked
    assert theirs.vsphere_target_id is None and theirs.docker_host_id == other.id
    assert any("owned by another integration" in w for w in s.warnings)

    vc.vms = []  # everything vanishes
    await reconcile_target(db_session, target)
    await db_session.refresh(mine)
    assert mine.vsphere_target_id is None  # operator-edited: released, kept
    assert str(mine.address) == "10.20.1.10"


@pytest.mark.asyncio
async def test_incomplete_read_deletes_nothing(db_session: AsyncSession, vc: Any) -> None:
    target, _ = await _setup(db_session)
    await reconcile_target(db_session, target)
    before = set(await _rows(db_session, target))

    vc.guest["vm-102"] = (500, {"error_type": "ERROR"})
    vc.vms = [v for v in vc.vms if v["vm"] != "vm-101"]  # vm-101 genuinely gone too
    s = await reconcile_target(db_session, target)
    assert s.ok and s.unreadable_vms == 1 and s.addresses_deleted == 0
    assert set(await _rows(db_session, target)) == before
    assert any("incomplete read" in w for w in s.warnings)


@pytest.mark.asyncio
async def test_vm_list_at_vcenters_cap_is_an_incomplete_read(
    db_session: AsyncSession, vc: Any
) -> None:
    target, _ = await _setup(db_session)
    await reconcile_target(db_session, target)
    before = set(await _rows(db_session, target))
    vc.vms = [
        {"vm": f"vm-{i}", "name": f"x{i}", "power_state": "POWERED_OFF"}
        for i in range(vclient.MAX_LIST_RESULTS)
    ]
    s = await reconcile_target(db_session, target)
    assert s.truncated and s.addresses_deleted == 0
    assert set(await _rows(db_session, target)) == before


@pytest.mark.asyncio
async def test_bad_credentials_are_reported_and_touch_nothing(
    db_session: AsyncSession, vc: Any
) -> None:
    target, _ = await _setup(db_session)
    await reconcile_target(db_session, target)
    before = set(await _rows(db_session, target))
    vc.overrides["/api/session"] = (401, {"error_type": "UNAUTHENTICATED"})
    s = await reconcile_target(db_session, target)
    assert not s.ok and "username or password rejected" in (target.last_sync_error or "")
    assert set(await _rows(db_session, target)) == before


@pytest.mark.asyncio
async def test_wrong_shape_vm_list_is_a_failed_read_not_zero_vms(
    db_session: AsyncSession, vc: Any
) -> None:
    target, _ = await _setup(db_session)
    await reconcile_target(db_session, target)
    before = set(await _rows(db_session, target))
    vc.vms = {"value": "proxy error page"}
    s = await reconcile_target(db_session, target)
    assert not s.ok
    assert set(await _rows(db_session, target)) == before


@pytest.mark.asyncio
async def test_trashed_subnet_is_not_resurrected_and_restores_cleanly(
    db_session: AsyncSession, vc: Any
) -> None:
    target, subnet = await _setup(db_session)
    await reconcile_target(db_session, target)
    subnet_id = subnet.id

    subnet.deleted_at = datetime.now(UTC)  # into Trash
    await db_session.flush()
    s = await reconcile_target(db_session, target)
    assert s.ok and s.addresses_created == 0
    assert s.skipped_no_subnet == 4  # nothing was written into the trashed subnet
    live = (
        (
            await db_session.execute(
                select(IPAddress).where(
                    IPAddress.vsphere_target_id == target.id, IPAddress.subnet_id != subnet_id
                )
            )
        )
        .scalars()
        .all()
    )
    assert live == []

    subnet.deleted_at = None  # restore
    await db_session.flush()
    s = await reconcile_target(db_session, target)
    assert s.ok and s.addresses_created == 0 and s.addresses_deleted == 0
    assert sorted(await _rows(db_session, target)) == ["10.20.0.11", "10.20.1.10", "10.20.1.20"]


@pytest.mark.asyncio
async def test_a_target_whose_space_is_in_trash_syncs_nothing(
    db_session: AsyncSession, vc: Any
) -> None:
    target, _ = await _setup(db_session)
    space = await db_session.get(IPSpace, target.ipam_space_id)
    assert space is not None
    space.deleted_at = datetime.now(UTC)
    await db_session.flush()
    s = await reconcile_target(db_session, target)
    assert not s.ok and s.error == SPACE_IN_TRASH_ERROR
    assert vc.calls == []  # not even a session was opened


@pytest.mark.asyncio
async def test_mirror_toggles(db_session: AsyncSession, vc: Any) -> None:
    target, _ = await _setup(db_session, mirror_vms=False)
    await reconcile_target(db_session, target)
    assert sorted(await _rows(db_session, target)) == ["10.20.0.11"]
    assert not any("guest" in p for _, p in vc.calls)  # no per-VM calls at all
    target.mirror_vms, target.mirror_hosts = True, False
    await reconcile_target(db_session, target)
    assert sorted(await _rows(db_session, target)) == ["10.20.1.10", "10.20.1.20"]
