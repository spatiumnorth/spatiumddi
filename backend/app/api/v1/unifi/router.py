"""UniFi Network integration CRUD + probe endpoints (issue #30).

Same shape as the Proxmox / Tailscale routers. Credentials are
Fernet-encrypted at rest; admin-only surface gated by the
``unifi_controller`` resource permission and the
``integrations.unifi`` feature module (the include in
``app/api/v1/router.py`` adds ``require_module``).

The probe endpoint is permissive about partial input — the
admin UI reuses it both for "test before save" (full body) and
"test the saved row" (``controller_id`` only, decrypts the
stored credentials). Any combination is fine as long as the
final tuple has enough auth material.
"""

from __future__ import annotations

import ssl
import uuid
from datetime import datetime
from typing import Any

import httpx
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, field_validator
from sqlalchemy import select

from app.api.deps import DB, CurrentUser, SuperAdmin
from app.api.v1._common import StatusResponse, add_trigger_audit
from app.core.celery_dispatch import dispatch
from app.core.crypto import decrypt_str, encrypt_str
from app.core.demo_mode import forbid_in_demo_mode
from app.core.header_credentials import header_secret
from app.core.permissions import require_resource_permission
from app.core.ssrf import assert_safe_target
from app.models.audit import AuditLog
from app.models.dns import DNSServerGroup
from app.models.ipam import IPAddress, IPSpace, Subnet
from app.models.unifi import UnifiController
from app.models.vlans import VLAN, Router
from app.services.integration_ownership import release_integration_rows

router = APIRouter(
    tags=["unifi"],
    dependencies=[Depends(require_resource_permission("unifi_controller"))],
)


# ── Pydantic schemas ─────────────────────────────────────────────────


_VALID_MODES = {"local", "cloud"}
_VALID_AUTH = {"api_key", "user_password"}


class _ControllerBase(BaseModel):
    name: str
    description: str = ""
    enabled: bool = True

    mode: str = "local"
    host: str | None = None
    port: int = 443
    cloud_host_id: str | None = None
    verify_tls: bool = True
    ca_bundle_pem: str = ""

    auth_kind: str = "api_key"

    ipam_space_id: uuid.UUID
    dns_group_id: uuid.UUID | None = None

    mirror_networks: bool = True
    mirror_clients: bool = True
    mirror_fixed_ips: bool = True
    site_allowlist: list[str] = []
    network_allowlist: dict[str, list[int]] = {}
    include_wired: bool = True
    include_wireless: bool = True
    include_vpn: bool = False

    sync_interval_seconds: int = 60

    @field_validator("mode")
    @classmethod
    def _valid_mode(cls, v: str) -> str:
        v = v.strip().lower()
        if v not in _VALID_MODES:
            raise ValueError(f"mode must be one of {sorted(_VALID_MODES)}")
        return v

    @field_validator("auth_kind")
    @classmethod
    def _valid_auth_kind(cls, v: str) -> str:
        v = v.strip().lower()
        if v not in _VALID_AUTH:
            raise ValueError(f"auth_kind must be one of {sorted(_VALID_AUTH)}")
        return v

    @field_validator("port")
    @classmethod
    def _valid_port(cls, v: int) -> int:
        if v < 1 or v > 65535:
            raise ValueError("port must be in 1..65535")
        return v

    @field_validator("sync_interval_seconds")
    @classmethod
    def _floor_interval(cls, v: int) -> int:
        if v < 30:
            raise ValueError("sync_interval_seconds must be ≥ 30")
        return v


class ControllerCreate(_ControllerBase):
    api_key: str = ""
    username: str = ""
    password: str = ""

    @field_validator("host")
    @classmethod
    def _strip_host(cls, v: str | None) -> str | None:
        if v is None:
            return None
        v = v.strip()
        if not v:
            return None
        if "://" in v:
            v = v.split("://", 1)[1]
        return v.rstrip("/")

    _check_api_key = field_validator("api_key")(header_secret)


class ControllerUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    enabled: bool | None = None
    mode: str | None = None
    host: str | None = None
    port: int | None = None
    cloud_host_id: str | None = None
    verify_tls: bool | None = None
    ca_bundle_pem: str | None = None
    auth_kind: str | None = None
    # Empty strings keep the stored credential; non-empty rotates.
    api_key: str | None = None
    username: str | None = None
    password: str | None = None
    ipam_space_id: uuid.UUID | None = None
    dns_group_id: uuid.UUID | None = None
    mirror_networks: bool | None = None
    mirror_clients: bool | None = None
    mirror_fixed_ips: bool | None = None
    site_allowlist: list[str] | None = None
    network_allowlist: dict[str, list[int]] | None = None
    include_wired: bool | None = None
    include_wireless: bool | None = None
    include_vpn: bool | None = None
    sync_interval_seconds: int | None = None

    _check_api_key = field_validator("api_key")(header_secret)


class ControllerResponse(BaseModel):
    id: uuid.UUID
    name: str
    description: str
    enabled: bool
    mode: str
    host: str | None
    port: int
    cloud_host_id: str | None
    verify_tls: bool
    ca_bundle_present: bool
    auth_kind: str
    api_key_present: bool
    username_present: bool
    password_present: bool
    ipam_space_id: uuid.UUID
    dns_group_id: uuid.UUID | None
    mirror_networks: bool
    mirror_clients: bool
    mirror_fixed_ips: bool
    site_allowlist: list[str]
    network_allowlist: dict[str, list[int]]
    include_wired: bool
    include_wireless: bool
    include_vpn: bool
    sync_interval_seconds: int
    last_synced_at: datetime | None
    last_sync_error: str | None
    controller_version: str | None
    site_count: int | None
    network_count: int | None
    client_count: int | None
    last_discovery: dict | None
    created_at: datetime
    modified_at: datetime


class TestConnectionRequest(BaseModel):
    controller_id: uuid.UUID | None = None
    mode: str | None = None
    host: str | None = None
    port: int | None = None
    cloud_host_id: str | None = None
    verify_tls: bool | None = None
    ca_bundle_pem: str | None = None
    auth_kind: str | None = None
    api_key: str | None = None
    username: str | None = None
    password: str | None = None

    _check_api_key = field_validator("api_key")(header_secret)


class TestConnectionResponse(BaseModel):
    ok: bool
    message: str
    controller_version: str | None = None
    site_count: int | None = None


# ── Helpers ──────────────────────────────────────────────────────────


def _to_response(c: UnifiController) -> ControllerResponse:
    return ControllerResponse(
        id=c.id,
        name=c.name,
        description=c.description,
        enabled=c.enabled,
        mode=c.mode,
        host=c.host,
        port=c.port,
        cloud_host_id=c.cloud_host_id,
        verify_tls=c.verify_tls,
        ca_bundle_present=bool(c.ca_bundle_pem),
        auth_kind=c.auth_kind,
        api_key_present=bool(c.api_key_encrypted),
        username_present=bool(c.username_encrypted),
        password_present=bool(c.password_encrypted),
        ipam_space_id=c.ipam_space_id,
        dns_group_id=c.dns_group_id,
        mirror_networks=c.mirror_networks,
        mirror_clients=c.mirror_clients,
        mirror_fixed_ips=c.mirror_fixed_ips,
        site_allowlist=list(c.site_allowlist or []),
        network_allowlist=dict(c.network_allowlist or {}),
        include_wired=c.include_wired,
        include_wireless=c.include_wireless,
        include_vpn=c.include_vpn,
        sync_interval_seconds=c.sync_interval_seconds,
        last_synced_at=c.last_synced_at,
        last_sync_error=c.last_sync_error,
        controller_version=c.controller_version,
        site_count=c.site_count,
        network_count=c.network_count,
        client_count=c.client_count,
        last_discovery=c.last_discovery,
        created_at=c.created_at,
        modified_at=c.modified_at,
    )


async def _validate_bindings(
    db: Any, ipam_space_id: uuid.UUID, dns_group_id: uuid.UUID | None
) -> None:
    space = await db.get(IPSpace, ipam_space_id)
    if space is None:
        raise HTTPException(status_code=422, detail="ipam_space_id not found")
    if dns_group_id is not None:
        group = await db.get(DNSServerGroup, dns_group_id)
        if group is None:
            raise HTTPException(status_code=422, detail="dns_group_id not found")


def _validate_mode_consistency(
    *,
    mode: str,
    host: str | None,
    cloud_host_id: str | None,
    auth_kind: str,
    api_key: str | None,
) -> None:
    if mode == "local":
        if not host:
            raise HTTPException(status_code=422, detail="local mode requires host")
    elif mode == "cloud":
        if not cloud_host_id:
            raise HTTPException(
                status_code=422,
                detail="cloud mode requires cloud_host_id (UniFi console UUID)",
            )
        if auth_kind != "api_key":
            raise HTTPException(
                status_code=422,
                detail="cloud mode requires auth_kind='api_key' (api.ui.com does not accept legacy login)",
            )
        if not api_key:
            raise HTTPException(
                status_code=422,
                detail="cloud mode requires api_key",
            )


def _audit(
    db: Any,
    *,
    user: Any,
    action: str,
    controller_id: uuid.UUID,
    controller_name: str,
    changed_fields: list[str] | None = None,
    new_value: dict | None = None,
) -> None:
    db.add(
        AuditLog(
            user_id=user.id if user else None,
            user_display_name=user.display_name if user else "system",
            auth_source=user.auth_source if user else "system",
            action=action,
            resource_type="unifi_controller",
            resource_id=str(controller_id),
            resource_display=controller_name,
            changed_fields=changed_fields,
            new_value=new_value,
        )
    )


async def _probe(
    *,
    mode: str,
    host: str | None,
    port: int,
    cloud_host_id: str | None,
    verify_tls: bool,
    ca_bundle_pem: str,
    auth_kind: str,
    api_key: str,
    username: str,
    password: str,
) -> TestConnectionResponse:
    """One-shot connection probe — returns a structured result, never
    raises. Hits the legacy ``self/sites`` endpoint because it works
    on both UniFi OS and pre-UniFi OS controllers and returns enough
    metadata to confirm auth is wired right.
    """
    verify: Any = verify_tls
    if verify_tls and ca_bundle_pem.strip():
        try:
            verify = ssl.create_default_context(cadata=ca_bundle_pem)
        except Exception as exc:  # noqa: BLE001
            return TestConnectionResponse(ok=False, message=f"CA bundle is invalid: {exc}")

    if mode == "cloud":
        base_url = "https://api.ui.com"
        sites_path = (
            f"/proxy/network/integration/v1/connector/consoles/{cloud_host_id}"
            f"/proxy/network/api/self/sites"
        )
        version_path = (
            f"/proxy/network/integration/v1/connector/consoles/{cloud_host_id}"
            f"/proxy/network/integration/v1/info"
        )
    else:
        base_url = f"https://{host}:{port}"
        sites_path = "/proxy/network/api/self/sites"
        version_path = "/proxy/network/integration/v1/info"

    headers: dict[str, str] = {"Accept": "application/json"}
    if auth_kind == "api_key" and api_key:
        headers["X-API-Key"] = api_key

    try:
        async with httpx.AsyncClient(
            base_url=base_url,
            headers=headers,
            verify=verify,
            timeout=10.0,
            follow_redirects=True,
        ) as client:
            # Legacy login (local + user_password only). Cloud always
            # rides on the API key.
            if auth_kind == "user_password" and mode == "local":
                login = await client.post(
                    "/api/login",
                    json={"username": username, "password": password, "remember": False},
                )
                if login.status_code == 401:
                    return TestConnectionResponse(
                        ok=False, message="HTTP 401 — username / password rejected"
                    )
                if login.status_code >= 400:
                    return TestConnectionResponse(
                        ok=False,
                        message=f"HTTP {login.status_code} on /api/login: {login.text[:200]}",
                    )

            ver = await client.get(version_path)
            controller_version: str | None = None
            if ver.status_code < 400:
                try:
                    body = ver.json()
                except ValueError:
                    body = None
                if isinstance(body, dict):
                    controller_version = (
                        str(body.get("applicationVersion") or body.get("version") or "") or None
                    )

            r = await client.get(sites_path)
            if r.status_code == 401:
                return TestConnectionResponse(
                    ok=False, message="HTTP 401 — credentials rejected by controller"
                )
            if r.status_code == 403:
                return TestConnectionResponse(
                    ok=False,
                    message="HTTP 403 — token does not have permission to list sites",
                )
            if r.status_code == 404:
                return TestConnectionResponse(
                    ok=False,
                    message=(
                        "HTTP 404 — endpoint not present on this controller. "
                        "Older controllers may need ``mode=local`` + ``auth_kind=user_password``."
                    ),
                )
            if r.status_code >= 400:
                return TestConnectionResponse(
                    ok=False, message=f"HTTP {r.status_code} from controller: {r.text[:200]}"
                )

            try:
                payload = r.json()
            except ValueError:
                return TestConnectionResponse(
                    ok=False, message=f"Non-JSON body from controller: {r.text[:200]}"
                )
            site_count = 0
            if isinstance(payload, dict) and isinstance(payload.get("data"), list):
                site_count = len(payload["data"])

            summary = "Connected"
            if controller_version:
                summary = f"Connected to UniFi {controller_version}"
            summary += f" — {site_count} site{'s' if site_count != 1 else ''}"
            return TestConnectionResponse(
                ok=True,
                message=summary,
                controller_version=controller_version,
                site_count=site_count,
            )
    except httpx.ConnectError as exc:
        return TestConnectionResponse(ok=False, message=f"Could not reach controller: {exc}")
    except ssl.SSLError as exc:
        return TestConnectionResponse(
            ok=False,
            message=(
                f"TLS error: {exc}. Upload the controller CA bundle, or disable "
                f"verify_tls for a self-signed lab host."
            ),
        )
    except httpx.HTTPError as exc:
        return TestConnectionResponse(ok=False, message=str(exc))
    except Exception as exc:  # noqa: BLE001
        return TestConnectionResponse(ok=False, message=str(exc))


# ── Endpoints ────────────────────────────────────────────────────────


@router.get("/controllers", response_model=list[ControllerResponse])
async def list_controllers(db: DB, _: CurrentUser) -> list[ControllerResponse]:
    res = await db.execute(select(UnifiController).order_by(UnifiController.name))
    return [_to_response(c) for c in res.scalars().all()]


@router.get("/controllers/{controller_id}", response_model=ControllerResponse)
async def get_controller(controller_id: uuid.UUID, db: DB, _: CurrentUser) -> ControllerResponse:
    c = await db.get(UnifiController, controller_id)
    if c is None:
        raise HTTPException(status_code=404, detail="UniFi controller not found")
    return _to_response(c)


# ── Dashboard payload ────────────────────────────────────────────────
#
# Single-shot endpoint backing the per-controller detail page. Returns
# the controller header + a denormalised view of every IPAM row owned
# by the controller (subnets, addresses), every VLAN under its
# auto-created Router, and the latest discovery snapshot. The page
# uses this to render Overview / Subnets / VLANs / Clients tabs
# without firing five queries on mount.


class DashboardSubnet(BaseModel):
    id: uuid.UUID
    network: str
    name: str
    description: str
    gateway: str | None
    vlan_id: int | None
    vlan_ref_id: uuid.UUID | None
    total_ips: int
    allocated_ips: int
    utilization_percent: float


class DashboardVlan(BaseModel):
    id: uuid.UUID
    vlan_id: int
    name: str
    description: str


class DashboardClient(BaseModel):
    id: uuid.UUID
    address: str
    subnet_id: uuid.UUID | None
    hostname: str | None
    mac_address: str | None
    status: str
    description: str
    last_seen_at: datetime | None


class DashboardResponse(BaseModel):
    controller: ControllerResponse
    router_id: uuid.UUID | None
    subnets: list[DashboardSubnet]
    vlans: list[DashboardVlan]
    clients: list[DashboardClient]
    client_count_total: int


@router.get(
    "/controllers/{controller_id}/dashboard",
    response_model=DashboardResponse,
)
async def get_controller_dashboard(
    controller_id: uuid.UUID, db: DB, _: CurrentUser
) -> DashboardResponse:
    """Render the full per-controller detail view in one round-trip.

    Subnets + VLANs are scoped to the controller's auto-created
    Router. Clients are capped at 500 newest first to keep the
    payload bounded — the full list is paginated through
    ``/ipam/addresses`` when the operator needs it.
    """
    c = await db.get(UnifiController, controller_id)
    if c is None:
        raise HTTPException(status_code=404, detail="UniFi controller not found")

    subnet_rows = (
        (
            await db.execute(
                select(Subnet)
                .where(Subnet.unifi_controller_id == c.id)
                .order_by(Subnet.network.asc())
            )
        )
        .scalars()
        .all()
    )
    subnets = [
        DashboardSubnet(
            id=s.id,
            network=str(s.network),
            name=s.name,
            description=s.description,
            gateway=str(s.gateway) if s.gateway else None,
            vlan_id=s.vlan_id,
            vlan_ref_id=s.vlan_ref_id,
            total_ips=s.total_ips,
            allocated_ips=s.allocated_ips,
            utilization_percent=s.utilization_percent,
        )
        for s in subnet_rows
    ]

    router_row = (
        await db.execute(select(Router).where(Router.unifi_controller_id == c.id))
    ).scalar_one_or_none()
    vlans: list[DashboardVlan] = []
    if router_row is not None:
        vlan_rows = (
            (
                await db.execute(
                    select(VLAN).where(VLAN.router_id == router_row.id).order_by(VLAN.vlan_id.asc())
                )
            )
            .scalars()
            .all()
        )
        vlans = [
            DashboardVlan(
                id=v.id,
                vlan_id=v.vlan_id,
                name=v.name,
                description=v.description,
            )
            for v in vlan_rows
        ]

    client_rows = (
        (
            await db.execute(
                select(IPAddress)
                .where(IPAddress.unifi_controller_id == c.id)
                .order_by(IPAddress.modified_at.desc())
                .limit(500)
            )
        )
        .scalars()
        .all()
    )
    clients = [
        DashboardClient(
            id=row.id,
            address=str(row.address),
            subnet_id=row.subnet_id,
            hostname=row.hostname or None,
            mac_address=row.mac_address or None,
            status=row.status,
            description=row.description or "",
            last_seen_at=getattr(row, "last_seen_at", None),
        )
        for row in client_rows
    ]
    client_count_total = c.client_count or len(client_rows)

    return DashboardResponse(
        controller=_to_response(c),
        router_id=router_row.id if router_row else None,
        subnets=subnets,
        vlans=vlans,
        clients=clients,
        client_count_total=client_count_total,
    )


@router.post(
    "/controllers",
    response_model=ControllerResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_controller(body: ControllerCreate, db: DB, user: SuperAdmin) -> ControllerResponse:
    forbid_in_demo_mode("UniFi controller registration is disabled")
    await _validate_bindings(db, body.ipam_space_id, body.dns_group_id)
    _validate_mode_consistency(
        mode=body.mode,
        host=body.host,
        cloud_host_id=body.cloud_host_id,
        auth_kind=body.auth_kind,
        api_key=body.api_key,
    )

    existing = await db.execute(select(UnifiController).where(UnifiController.name == body.name))
    if existing.scalar_one_or_none() is not None:
        raise HTTPException(status_code=409, detail="A UniFi controller with that name exists")

    c = UnifiController(
        name=body.name,
        description=body.description,
        enabled=body.enabled,
        mode=body.mode,
        host=body.host,
        port=body.port,
        cloud_host_id=body.cloud_host_id,
        verify_tls=body.verify_tls,
        ca_bundle_pem=body.ca_bundle_pem,
        auth_kind=body.auth_kind,
        api_key_encrypted=encrypt_str(body.api_key) if body.api_key else b"",
        username_encrypted=encrypt_str(body.username) if body.username else b"",
        password_encrypted=encrypt_str(body.password) if body.password else b"",
        ipam_space_id=body.ipam_space_id,
        dns_group_id=body.dns_group_id,
        mirror_networks=body.mirror_networks,
        mirror_clients=body.mirror_clients,
        mirror_fixed_ips=body.mirror_fixed_ips,
        site_allowlist=body.site_allowlist,
        network_allowlist=body.network_allowlist,
        include_wired=body.include_wired,
        include_wireless=body.include_wireless,
        include_vpn=body.include_vpn,
        sync_interval_seconds=body.sync_interval_seconds,
    )
    db.add(c)
    await db.flush()
    _audit(
        db,
        user=user,
        action="create",
        controller_id=c.id,
        controller_name=c.name,
        new_value=body.model_dump(mode="json", exclude={"api_key", "username", "password"}),
    )
    await db.commit()
    await db.refresh(c)
    return _to_response(c)


@router.put("/controllers/{controller_id}", response_model=ControllerResponse)
async def update_controller(
    controller_id: uuid.UUID, body: ControllerUpdate, db: DB, user: SuperAdmin
) -> ControllerResponse:
    c = await db.get(UnifiController, controller_id)
    if c is None:
        raise HTTPException(status_code=404, detail="UniFi controller not found")

    changes = body.model_dump(exclude_unset=True)
    new_ipam = changes.get("ipam_space_id", c.ipam_space_id)
    new_dns = changes.get("dns_group_id", c.dns_group_id)
    if "ipam_space_id" in changes or "dns_group_id" in changes:
        await _validate_bindings(db, new_ipam, new_dns)

    # Validate the post-change mode consistency. Use post-change values
    # by overlaying ``changes`` on the row's current state.
    post = {
        "mode": changes.get("mode", c.mode),
        "host": changes.get("host", c.host),
        "cloud_host_id": changes.get("cloud_host_id", c.cloud_host_id),
        "auth_kind": changes.get("auth_kind", c.auth_kind),
    }
    # api_key presence: if rotating we use the new one; else fall back
    # to "is one stored?".
    incoming_api_key = changes.get("api_key")
    api_key_value = (
        incoming_api_key
        if incoming_api_key is not None
        else ("present" if c.api_key_encrypted else "")
    )
    _validate_mode_consistency(
        mode=post["mode"],
        host=post["host"],
        cloud_host_id=post["cloud_host_id"],
        auth_kind=post["auth_kind"],
        api_key=api_key_value,
    )

    for k, v in changes.items():
        if k == "api_key":
            if v:
                c.api_key_encrypted = encrypt_str(v)
        elif k == "username":
            if v:
                c.username_encrypted = encrypt_str(v)
        elif k == "password":
            if v:
                c.password_encrypted = encrypt_str(v)
        else:
            setattr(c, k, v)

    _audit(
        db,
        user=user,
        action="update",
        controller_id=c.id,
        controller_name=c.name,
        changed_fields=list(changes.keys()),
        new_value={
            k: v for k, v in changes.items() if k not in {"api_key", "username", "password"}
        },
    )
    await db.commit()
    await db.refresh(c)
    return _to_response(c)


@router.delete("/controllers/{controller_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_controller(
    controller_id: uuid.UUID, db: DB, user: SuperAdmin, force: bool = False
) -> None:
    c = await db.get(UnifiController, controller_id)
    if c is None:
        raise HTTPException(status_code=404, detail="UniFi controller not found")
    from app.services.block_sync.delete_guard import (  # noqa: PLC0415
        assert_block_sync_deletable,
    )

    await assert_block_sync_deletable(
        db,
        target_kind="unifi",
        target_id=c.id,
        armed=c.block_sync_enabled,
        force=force,
    )
    # #601 — sweep any active block-sync push rows for this target (polymorphic
    # target_id, no cascade). Disarm the target first if the controller should
    # stop quarantining the MACs (disarm lifts them; delete does not).
    from sqlalchemy import delete as sa_delete  # noqa: PLC0415

    from app.models.block_sync import NetworkBlockPush  # noqa: PLC0415

    await db.execute(
        sa_delete(NetworkBlockPush).where(
            NetworkBlockPush.target_kind == "unifi",
            NetworkBlockPush.target_id == c.id,
        )
    )
    _audit(db, user=user, action="delete", controller_id=c.id, controller_name=c.name)
    # #2287 — hand back operator-made rows in mirrored subnets / blocks before
    # the FK cascade can destroy them.
    await release_integration_rows(
        db, own_fk="unifi_controller_id", target_id=c.id, user=user, target_name=c.name
    )
    await db.delete(c)
    await db.commit()


@router.post(
    "/controllers/{controller_id}/sync",
    status_code=status.HTTP_202_ACCEPTED,
)
async def sync_controller(controller_id: uuid.UUID, db: DB, user: SuperAdmin) -> StatusResponse:
    c = await db.get(UnifiController, controller_id)
    if c is None:
        raise HTTPException(status_code=404, detail="UniFi controller not found")

    add_trigger_audit(
        db,
        user,
        resource_type="unifi_controller",
        resource_id=c.id,
        resource_display=str(getattr(c, "name", None) or c.id),
        action="sync",
    )
    await db.commit()

    from app.tasks.unifi_sync import sync_controller_now  # noqa: PLC0415

    try:
        result = await dispatch(sync_controller_now, str(c.id))
        return StatusResponse(status="queued", task_id=result.id)
    except Exception:  # noqa: BLE001
        return StatusResponse(status="broker_unavailable", task_id="")


@router.post("/controllers/test", response_model=TestConnectionResponse)
async def test_connection(
    body: TestConnectionRequest, db: DB, _: SuperAdmin
) -> TestConnectionResponse:
    mode = body.mode
    host = body.host
    port = body.port or 443
    cloud_host_id = body.cloud_host_id
    verify_tls = body.verify_tls if body.verify_tls is not None else True
    ca_bundle_pem = body.ca_bundle_pem
    auth_kind = body.auth_kind
    api_key = body.api_key
    username = body.username
    password = body.password

    if body.controller_id is not None:
        stored = await db.get(UnifiController, body.controller_id)
        if stored is None:
            raise HTTPException(status_code=404, detail="UniFi controller not found")
        mode = mode or stored.mode
        host = host or stored.host
        port = body.port or stored.port
        cloud_host_id = cloud_host_id or stored.cloud_host_id
        verify_tls = body.verify_tls if body.verify_tls is not None else stored.verify_tls
        ca_bundle_pem = ca_bundle_pem if ca_bundle_pem is not None else stored.ca_bundle_pem
        auth_kind = auth_kind or stored.auth_kind
        if not api_key and stored.api_key_encrypted:
            try:
                api_key = decrypt_str(stored.api_key_encrypted)
            except ValueError as exc:
                raise HTTPException(
                    status_code=500,
                    detail="Stored api_key could not be decrypted — re-enter it",
                ) from exc
        if not username and stored.username_encrypted:
            try:
                username = decrypt_str(stored.username_encrypted)
            except ValueError as exc:
                raise HTTPException(
                    status_code=500,
                    detail="Stored username could not be decrypted — re-enter it",
                ) from exc
        if not password and stored.password_encrypted:
            try:
                password = decrypt_str(stored.password_encrypted)
            except ValueError as exc:
                raise HTTPException(
                    status_code=500,
                    detail="Stored password could not be decrypted — re-enter it",
                ) from exc

    mode = (mode or "local").lower()
    auth_kind = (auth_kind or "api_key").lower()

    if mode == "local" and not host:
        raise HTTPException(status_code=422, detail="host required for local mode")
    if mode == "cloud" and not cloud_host_id:
        raise HTTPException(status_code=422, detail="cloud_host_id required for cloud mode")
    if auth_kind == "api_key" and not api_key:
        raise HTTPException(status_code=422, detail="api_key required for auth_kind='api_key'")
    if auth_kind == "user_password" and (not username or not password):
        raise HTTPException(
            status_code=422,
            detail="username + password required for auth_kind='user_password'",
        )

    # SECURITY (#400, L5): advisory SSRF guard — log the resolved
    # controller IP for local-mode probes (cloud mode dials UniFi's
    # hosted API, not an operator-supplied host). Not hard-blocked:
    # local controllers sit on the RFC1918 LAN.
    if mode == "local" and host:
        assert_safe_target(host, label="unifi")

    result = await _probe(
        mode=mode,
        host=host,
        port=port,
        cloud_host_id=cloud_host_id,
        verify_tls=verify_tls,
        ca_bundle_pem=ca_bundle_pem or "",
        auth_kind=auth_kind,
        api_key=api_key or "",
        username=username or "",
        password=password or "",
    )

    if body.controller_id is not None and result.ok:
        stored = await db.get(UnifiController, body.controller_id)
        if stored is not None:
            stored.controller_version = result.controller_version
            stored.site_count = result.site_count
            stored.last_sync_error = None
            await db.commit()

    return result


__all__ = ["router"]
