"""Wake-on-LAN magic packet (issue #533).

Pure-Python magic-packet build + UDP broadcast send. The control-plane
(server vantage) uses this directly; the appliance vantage runs an
equivalent ``_run_wol`` on the supervisor agent so the packet originates
on the target's L2 segment (WoL only wakes a NIC that receives the frame
on its own broadcast domain).

WoL is IPv4-only here: the magic packet rides a UDP broadcast and IPv6 has
no broadcast address. The 102-byte AMD Magic Packet is 6×0xFF followed by
16 repetitions of the target MAC.
"""

from __future__ import annotations

import asyncio
import ipaddress
import re
import socket
import uuid
from typing import TYPE_CHECKING

from pydantic import BaseModel, Field, field_validator

from app.services.nettools.schemas import NetToolTarget, is_blocked_target

if TYPE_CHECKING:
    import uuid as _uuid_t

    from sqlalchemy.ext.asyncio import AsyncSession

    from app.models.ipam import IPAddress

_HEX12_RE = re.compile(r"^[0-9A-Fa-f]{12}$")


def vantage_to_jsonb(target: NetToolTarget | None) -> dict[str, object]:
    """Canonical ``{kind, id}`` JSONB for a run/target ``vantage`` column.

    The single serializer for the wake vantage wire shape — shared by the
    scheduler router and the ad-hoc IPAM wake so the shape can't drift between
    them. ``None`` (or a ``server`` target) is the control-plane vantage; an
    appliance target stringifies its id.
    """
    if target is None:
        return {"kind": "server", "id": None}
    return {"kind": target.kind, "id": str(target.id) if target.id is not None else None}


def normalize_mac(mac: str) -> str:
    """Return the canonical lowercase colon form (``aa:bb:cc:dd:ee:ff``).

    Accepts colon / hyphen / dot separators or a bare 12-hex string.
    Raises ``ValueError`` on anything else so callers can surface a 422.
    """
    stripped = re.sub(r"[:.\-]", "", mac.strip())
    if not _HEX12_RE.match(stripped):
        raise ValueError(f"not a valid MAC address: {mac!r}")
    low = stripped.lower()
    return ":".join(low[i : i + 2] for i in range(0, 12, 2))


def build_magic_packet(mac: str) -> bytes:
    """Build the 102-byte AMD Magic Packet for ``mac``."""
    mac_bytes = bytes.fromhex(normalize_mac(mac).replace(":", ""))
    return b"\xff" * 6 + mac_bytes * 16


def _send_sync(packet: bytes, broadcast: str, port: int) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.sendto(packet, (broadcast, port))


async def send_magic_packet(mac: str, broadcast: str, port: int = 9) -> None:
    """Build + broadcast the magic packet, off the event loop.

    ``broadcast`` is the IPv4 broadcast address to send to (the subnet's
    directed broadcast, or ``255.255.255.255`` for the local segment);
    ``port`` is conventionally 9 (discard) or 7 (echo).
    """
    packet = build_magic_packet(mac)
    await asyncio.to_thread(_send_sync, packet, broadcast, port)


class WolWireRequest(BaseModel):
    """Params shipped to (and re-validated on) an appliance agent, and the
    validated shape the server-vantage send uses. Validators double as the
    SSRF/arg guard: a bad MAC or non-IPv4 broadcast is rejected before any
    packet is built."""

    mac: str
    broadcast: str
    port: int = Field(default=9, ge=1, le=65535)

    @field_validator("mac")
    @classmethod
    def _v_mac(cls, v: str) -> str:
        return normalize_mac(v)

    @field_validator("broadcast")
    @classmethod
    def _v_broadcast(cls, v: str) -> str:
        try:
            canonical = str(ipaddress.IPv4Address(v.strip()))
        except ipaddress.AddressValueError as exc:
            raise ValueError(f"broadcast must be an IPv4 address: {v!r}") from exc
        # Apply the same SSRF denylist the other network tools use so WoL can't
        # fire a UDP payload at loopback / link-local / metadata ranges (a
        # legit broadcast — 255.255.255.255 or an RFC1918 directed broadcast —
        # is never in a blocked range, so this doesn't reject real use).
        if is_blocked_target(canonical):
            raise ValueError(
                f"broadcast {canonical} is in a blocked range (loopback / "
                "link-local / cloud-metadata) and cannot be targeted"
            )
        return canonical


class WolResult(BaseModel):
    """Uniform WoL send result. ``ran_from`` mirrors the network-tools
    convention: ``server`` for the api-container send, ``appliance:<name>``
    when a Fleet appliance sent it."""

    mac: str
    broadcast: str
    port: int
    sent: bool
    ran_from: str = "server"
    error: str | None = None


class WolTargetError(ValueError):
    """A wake target couldn't be resolved. ``not_found`` distinguishes a
    missing row (→ 404) from a present-but-unwakeable one (→ 422)."""

    def __init__(self, message: str, *, not_found: bool = False) -> None:
        super().__init__(message)
        self.not_found = not_found


def broadcast_for_network(network: str) -> str:
    """Directed broadcast of an IPv4 subnet; the limited broadcast
    (255.255.255.255) for an IPv6 subnet, which has no broadcast of its own —
    the magic packet is L2 and the target MAC is what wakes the NIC, so the
    local-segment broadcast still delivers it."""
    net = ipaddress.ip_network(network, strict=False)
    if isinstance(net, ipaddress.IPv6Network):
        return "255.255.255.255"
    return str(net.broadcast_address)


async def resolve_wake_params(
    db: AsyncSession, address_id: uuid.UUID
) -> tuple[IPAddress, str, str]:
    """Load the IP, require a MAC, and derive ``(ip_row, mac, broadcast)``.

    Single source of truth shared by the REST endpoint and the AI operation so
    the resolution + error messages don't drift. Raises :class:`WolTargetError`.
    """
    from app.models.ipam import Subnet  # noqa: PLC0415 — avoid import cycle
    from app.services.ipam.live_address import get_live_address  # noqa: PLC0415

    # #3537: an address whose subnet is in the Trash is not found, before the
    # MAC check, so it answers 404 like every other route keyed on its id.
    ip = await get_live_address(db, address_id)
    if ip is None:
        raise WolTargetError("IP address not found", not_found=True)
    if not ip.mac_address:
        raise WolTargetError("This IP has no MAC address on record — Wake-on-LAN needs one.")
    subnet = await db.get(Subnet, ip.subnet_id)
    if subnet is None:
        raise WolTargetError("Subnet not found", not_found=True)
    broadcast = broadcast_for_network(str(subnet.network))
    # A loopback / link-local subnet would derive a blocked broadcast — refuse
    # cleanly (422) rather than letting the wire-schema validator 500 later.
    if is_blocked_target(broadcast):
        raise WolTargetError(f"Subnet {subnet.network} derives a blocked broadcast ({broadcast}).")
    return ip, normalize_mac(str(ip.mac_address)), broadcast


class WolDispatchError(Exception):
    """A send failed. ``status`` is the HTTP status the API layer should map
    to (kept out of the raise sites so callers translate it uniformly)."""

    def __init__(self, message: str, status: int) -> None:
        super().__init__(message)
        self.status = status


async def wake_from_server(wire: WolWireRequest) -> WolResult:
    """Broadcast the magic packet from the control-plane container. Raises
    :class:`WolDispatchError` (502) when there's no route to the broadcast —
    the documented single-box limitation — rather than a bare OSError."""
    try:
        await send_magic_packet(wire.mac, wire.broadcast, wire.port)
    except OSError as exc:
        raise WolDispatchError(
            f"Could not broadcast the magic packet from the server: {exc}. "
            "Try an appliance vantage on the target's segment.",
            502,
        ) from exc
    return WolResult(
        mac=wire.mac, broadcast=wire.broadcast, port=wire.port, sent=True, ran_from="server"
    )


async def wake_via_appliance(
    db: AsyncSession, appliance_id: _uuid_t.UUID, wire: WolWireRequest
) -> WolResult:
    """Dispatch the send to a Fleet appliance so the packet originates on the
    target's segment. Reuses the generic nettool command channel. Raises
    :class:`WolDispatchError` (404 / 503 / 504 / 502) on any failure."""
    from app.models.appliance import Appliance  # noqa: PLC0415 — avoid import cycle
    from app.services.appliance import agent_cmd  # noqa: PLC0415

    appliance = await db.get(Appliance, appliance_id)
    if appliance is None:
        raise WolDispatchError("Appliance not found.", 404)
    ready = agent_cmd.appliance_ready(state=appliance.state, last_seen_at=appliance.last_seen_at)
    try:
        outcome = await agent_cmd.enqueue_command(
            appliance.id,
            "wol",
            wire.model_dump(mode="json"),
            ready=ready,
            # Match the sibling nettool dispatch — a busy supervisor mid-poll
            # needs headroom or a healthy appliance 504s.
            timeout=30.0,
        )
    except agent_cmd.ApplianceOffline as exc:
        raise WolDispatchError(
            f"Appliance {appliance.hostname!r} is offline or not approved.", 503
        ) from exc
    except TimeoutError as exc:
        raise WolDispatchError(
            f"Appliance {appliance.hostname!r} did not send the packet in time.", 504
        ) from exc
    if outcome.error is not None or outcome.result is None:
        raise WolDispatchError(
            f"Appliance {appliance.hostname!r} could not send the magic packet: "
            f"{outcome.error or 'no result returned'}",
            502,
        )
    result = WolResult.model_validate(outcome.result)
    return result.model_copy(update={"ran_from": f"appliance:{appliance.hostname}"})
