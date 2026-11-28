"""Additional network interfaces on the appliance (#4428).

The appliance's PRIMARY connection belongs to the installer: STATE,
``spatium-etc-render`` and NetworkManager's ``10-spatium-*`` keyfiles own
it, and the console's F4 edits it. Everything else a deployment needs —
a second NIC on a DHCP VLAN, an 802.1Q sub-interface, the route back to
a relay's ``giaddr`` subnet — had to be added by hand with ``nmcli``.
This module is the control-plane half of managing those from the API.

It is the ONLY place the desired set is validated, bundled for the
heartbeat and joined against what the node reports, so the REST surface,
the Fleet UI and the copilot tools cannot disagree about what is allowed
or what state an interface is in — the ``removable`` / ``storage_health``
shape.

What makes this plane different from its siblings is that **a wrong
setting can cut the node off from the control plane**, and a node cut off
cannot be told to undo it. Three layers, in descending order of trust:

1. **The primary interface cannot be managed at all.** The renderer,
   the installer and ``spatium-network-adopt`` own it, and two writers of
   one profile is how a node ends up with an address nobody chose. It is
   identified from three independent signals (STATE's interface, the
   interface carrying the default route, the interface carrying the
   node's k3s address) plus whatever it is stacked on, because any one of
   them can be absent on a node that is mid-change.
2. **Nothing may overlap, shadow or hijack the paths the node already
   uses.** An address overlapping another interface's subnet makes the
   kernel's choice of egress arbitrary; a route covering the node's own
   cluster address or the pod / service CIDR would send cluster traffic
   out of the wrong port. A default route through an extra interface is
   refused outright rather than reasoned about.
3. **Whatever gets through is applied with a rollback.** The host runner
   snapshots the previous profiles and reverts them unless the control
   plane is still reachable afterwards (see ``spatiumddi-netif-reload``).
   That layer exists because layers 1 and 2 are checks on a model of the
   network; this one is a check on the network.

A node that has never reported its inventory is UNKNOWN, never "empty":
every check above needs to know what the node already has, so a write is
refused with a 409 rather than validated against nothing.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from dataclasses import dataclass, field
from typing import Any

#: How long the host waits for the control plane to confirm an apply
#: before it restores the previous profiles. Long enough for NM to bring a
#: link up and for one heartbeat (long-poll included) to get through; short
#: enough that an operator staring at a dead node is not waiting minutes.
REVERT_SECONDS = 180

MAX_INTERFACES = 16
MAX_ADDRESSES = 8
MAX_ROUTES = 32

#: Linux IFNAMSIZ is 16 including the terminating NUL.
_IFNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,14}$")

#: Inventory kinds a VLAN may be stacked on.
VLAN_PARENT_KINDS = ("ethernet", "bond", "bridge")

KINDS = ("ethernet", "vlan")


class NetifError(ValueError):
    """An operator-facing refusal, complete enough to act on."""


# ── Reported inventory ────────────────────────────────────────────────


def report(cluster_health: Any) -> dict[str, Any] | None:
    """The supervisor's reported ``netif`` block, or None if unreported.

    None is UNKNOWN: a supervisor too old to look reports nothing, and
    rendering that as "no interfaces" would validate a change against an
    empty network.
    """
    if not isinstance(cluster_health, dict):
        return None
    block = cluster_health.get("netif")
    return block if isinstance(block, dict) else None


def _inventory(cluster_health: Any) -> dict[str, Any] | None:
    block = report(cluster_health)
    inv = (block or {}).get("inventory")
    return inv if isinstance(inv, dict) else None


def has_inventory(cluster_health: Any) -> bool:
    return _inventory(cluster_health) is not None


def _s(value: Any, limit: int = 200) -> str:
    return str(value)[:limit] if value is not None else ""


def _int(value: Any) -> int | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return int(value)


def nic_fields(entry: Any) -> dict[str, Any]:
    """One reported interface, coerced field by field.

    ``cluster_health`` is stored verbatim with no inner-shape validation,
    so every value is coerced here before it reaches a typed response
    field — one wrong type from a supervisor must not 500 the page that
    would let the operator fix it.
    """
    data = entry if isinstance(entry, dict) else {}
    addrs = data.get("addresses")
    return {
        "name": _s(data.get("name"), 32),
        "kind": _s(data.get("kind"), 16) or "other",
        "parent": _s(data["parent"], 32) if data.get("parent") else None,
        "vlan_id": _int(data.get("vlan_id")),
        "master": _s(data["master"], 32) if data.get("master") else None,
        "state": _s(data.get("state"), 16) or "unknown",
        "carrier": data["carrier"] if isinstance(data.get("carrier"), bool) else None,
        "mtu": _int(data.get("mtu")),
        "mac": _s(data.get("mac"), 32) or None,
        "addresses": (
            [_s(a, 64) for a in addrs if isinstance(a, str)][:32] if isinstance(addrs, list) else []
        ),
    }


def route_fields(entry: Any) -> dict[str, Any]:
    data = entry if isinstance(entry, dict) else {}
    return {
        "destination": _s(data.get("dst"), 64),
        "gateway": _s(data["gateway"], 64) if data.get("gateway") else None,
        "dev": _s(data.get("dev"), 32) or None,
        "metric": _int(data.get("metric")),
        "protocol": _s(data.get("protocol"), 16) or None,
    }


def inventory_nics(cluster_health: Any) -> list[dict[str, Any]]:
    inv = _inventory(cluster_health)
    if inv is None:
        return []
    return [nic_fields(e) for e in inv.get("interfaces") or [] if isinstance(e, dict)]


def inventory_routes(cluster_health: Any) -> list[dict[str, Any]]:
    inv = _inventory(cluster_health)
    if inv is None:
        return []
    return [route_fields(e) for e in inv.get("routes") or [] if isinstance(e, dict)]


def _net(text: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network | None:
    try:
        return ipaddress.ip_interface(text).network
    except ValueError:
        try:
            return ipaddress.ip_network(text, strict=False)
        except ValueError:
            return None


def _overlaps(a: Any, b: Any) -> bool:
    return a.version == b.version and a.overlaps(b)


# ── Validation context ────────────────────────────────────────────────


@dataclass
class NetifContext:
    """What the node already has, as far as it has told us."""

    #: name -> kind for every interface the node reports.
    kinds: dict[str, str] = field(default_factory=dict)
    #: name -> MTU the node reports.
    mtus: dict[str, int] = field(default_factory=dict)
    #: VLAN name -> (parent, vlan id) for the VLANs the node already has.
    vlans: dict[str, tuple[str, int]] = field(default_factory=dict)
    #: name -> bond / bridge it is enslaved to.
    masters: dict[str, str] = field(default_factory=dict)
    #: name -> why it cannot be managed.
    protected: dict[str, str] = field(default_factory=dict)
    #: (network, "iface") for every address / connected route the node has
    #: on an interface this feature does NOT manage.
    foreign: list[tuple[Any, str]] = field(default_factory=list)
    #: Networks no route may cover or address overlap: the node's own
    #: cluster addresses and the pod / service CIDRs.
    reserved: list[tuple[Any, str]] = field(default_factory=list)


def build_context(
    cluster_health: Any,
    *,
    node_ips: list[str] | None = None,
    pod_cidr: str | None = None,
    service_cidr: str | None = None,
    managed_names: set[str] | None = None,
) -> NetifContext:
    """Derive the validation context from the node's last report.

    ``managed_names`` are the interfaces currently in the DESIRED set (or
    the one being written): their own addresses must not count as
    "foreign", or re-saving an unchanged config would refuse itself.
    """
    managed = managed_names or set()
    ctx = NetifContext()
    nics = inventory_nics(cluster_health)
    by_name = {n["name"]: n for n in nics if n["name"]}
    inv = _inventory(cluster_health) or {}

    for n in nics:
        if not n["name"]:
            continue
        ctx.kinds[n["name"]] = n["kind"]
        if n["mtu"] is not None:
            ctx.mtus[n["name"]] = n["mtu"]
        if n["master"]:
            ctx.masters[n["name"]] = n["master"]
        if n["kind"] == "vlan" and n["parent"] and n["vlan_id"] is not None:
            ctx.vlans[n["name"]] = (n["parent"], n["vlan_id"])

    # ── who is the primary? Three signals, any one is enough. ──
    def protect(name: str | None, why: str) -> None:
        if name and name not in ctx.protected:
            ctx.protected[name] = why

    primary = _s(inv.get("primary_interface"), 32) or None
    protect(
        primary,
        "it is the appliance's primary interface, owned by the installer "
        "(change it with the console's F4 screen)",
    )
    default_devs = inv.get("default_devs")
    if isinstance(default_devs, list):
        for dev in default_devs:
            protect(_s(dev, 32), "it carries the node's default route")
    cluster_ips: list[Any] = []
    for raw in node_ips or []:
        try:
            cluster_ips.append(ipaddress.ip_address(raw))
        except ValueError:
            continue
    for n in nics:
        for a in n["addresses"]:
            try:
                ip = ipaddress.ip_interface(a).ip
            except ValueError:
                continue
            if ip in cluster_ips:
                protect(n["name"], "it carries the node's cluster address")

    # Whatever a protected interface is stacked on, or made of, goes with it.
    changed = True
    while changed:
        changed = False
        for name in list(ctx.protected):
            n = by_name.get(name)
            if not n:
                continue
            for dep in (n["parent"], n["master"]):
                if dep and dep not in ctx.protected:
                    ctx.protected[dep] = f"it is the parent of {name}, which is protected"
                    changed = True
        for n in nics:
            master = n["master"]
            if master and master in ctx.protected and n["name"] not in ctx.protected:
                ctx.protected[n["name"]] = f"it is a member of {master}, which is protected"
                changed = True

    # ── what is already routed / addressed, minus what we manage ──
    for n in nics:
        if n["name"] in managed:
            continue
        for a in n["addresses"]:
            net = _net(a)
            if net is not None and not net.is_link_local:
                ctx.foreign.append((net, n["name"]))
    for r in inventory_routes(cluster_health):
        if r["dev"] in managed:
            continue
        net = _net(r["destination"]) if r["destination"] not in ("", "default") else None
        if net is not None and net.prefixlen > 0 and not net.is_link_local:
            ctx.foreign.append((net, r["dev"] or "a route"))

    for raw in node_ips or []:
        net = _net(raw)
        if net is not None:
            ctx.reserved.append((net, "the node's cluster address"))
    for label, cidr in (("the pod CIDR", pod_cidr), ("the service CIDR", service_cidr)):
        for part in (cidr or "").split(","):
            net = _net(part.strip()) if part.strip() else None
            if net is not None:
                ctx.reserved.append((net, label))
    return ctx


# ── Structural validation (no knowledge of the node) ─────────────────


def _validate_address(text: Any, where: str) -> str:
    if not isinstance(text, str) or "/" not in text:
        raise NetifError(
            f"{where}: {text!r} is not an address with a prefix length, e.g. 10.9.0.2/24"
        )
    try:
        iface = ipaddress.ip_interface(text.strip())
    except ValueError as exc:
        raise NetifError(f"{where}: {text!r} is not a valid address ({exc})") from exc
    ip = iface.ip
    if ip.is_unspecified or ip.is_loopback or ip.is_multicast:
        raise NetifError(f"{where}: {text!r} is not a usable unicast address")
    if ip.is_link_local:
        raise NetifError(
            f"{where}: {text!r} is a link-local address; the host assigns those itself"
        )
    net = iface.network
    if ip.version == 4:
        if iface.network.prefixlen < 8:
            raise NetifError(f"{where}: /{net.prefixlen} is too wide for an interface address")
        if net.prefixlen < 31 and (ip == net.network_address or ip == net.broadcast_address):
            raise NetifError(
                f"{where}: {text!r} is the network or broadcast address of {net}, "
                "not a host address"
            )
    else:
        if net.prefixlen < 8:
            raise NetifError(f"{where}: /{net.prefixlen} is too wide for an interface address")
    return str(iface)


def _validate_route(raw: Any, where: str, addresses: list[str]) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise NetifError(f"{where}: each route must be an object")
    dest_text = str(raw.get("destination") or "").strip()
    gw_text = str(raw.get("gateway") or "").strip()
    try:
        dest = ipaddress.ip_network(dest_text, strict=False)
    except ValueError as exc:
        raise NetifError(f"{where}: {dest_text!r} is not a valid destination network") from exc
    if dest.prefixlen == 0:
        raise NetifError(
            f"{where}: a default route ({dest}) through an additional interface is "
            "refused — it would compete with the management path. Add the specific "
            "networks you need instead (for example the DHCP relay's subnet)."
        )
    if dest.is_loopback or dest.is_multicast or dest.is_link_local:
        raise NetifError(f"{where}: {dest} is not a routable destination")
    if not gw_text:
        raise NetifError(f"{where}: a gateway is required for the route to {dest}")
    try:
        gw = ipaddress.ip_address(gw_text)
    except ValueError as exc:
        raise NetifError(f"{where}: {gw_text!r} is not a valid gateway address") from exc
    if gw.version != dest.version:
        raise NetifError(f"{where}: the gateway {gw} and the destination {dest} differ in family")
    # On-link: the gateway has to sit inside a connected subnet of THIS
    # interface, or the kernel refuses the route and the apply half-fails.
    # A v6 link-local gateway is on-link by definition.
    connected = [ipaddress.ip_interface(a).network for a in addresses]
    if not (gw.is_link_local and gw.version == 6) and not any(
        gw in net for net in connected if net.version == gw.version
    ):
        raise NetifError(
            f"{where}: the gateway {gw} is not inside any subnet configured on this "
            "interface, so it is not reachable directly"
        )
    if any(gw == ipaddress.ip_interface(a).ip for a in addresses):
        raise NetifError(f"{where}: the gateway {gw} is this interface's own address")
    metric = raw.get("metric")
    if metric is not None:
        if isinstance(metric, bool) or not isinstance(metric, int) or not 1 <= metric <= 65535:
            raise NetifError(f"{where}: the metric must be a whole number from 1 to 65535")
    return {"destination": str(dest), "gateway": str(gw), "metric": metric}


def normalise_desired(entries: Any) -> list[dict[str, Any]]:
    """Validate the desired list's own shape, raising on the first fault.

    Needs nothing from the node, so it is also what the heartbeat bundle
    runs: a stored set that stops validating must not 500 the heartbeat.
    """
    if not isinstance(entries, list):
        raise NetifError("the interface list must be a list")
    if len(entries) > MAX_INTERFACES:
        raise NetifError(f"at most {MAX_INTERFACES} interfaces can be managed on one node")
    out: list[dict[str, Any]] = []
    names: set[str] = set()
    vlans: set[tuple[str, int]] = set()
    for raw in entries:
        if not isinstance(raw, dict):
            raise NetifError("each interface must be an object")
        kind = str(raw.get("kind") or "ethernet").strip().lower()
        if kind not in KINDS:
            raise NetifError(f"{kind!r} is not a supported kind — use one of {', '.join(KINDS)}")
        parent: str | None = None
        vlan_id: int | None = None
        name = str(raw.get("name") or "").strip()
        if kind == "vlan":
            parent = str(raw.get("parent") or "").strip()
            if not parent:
                raise NetifError("a VLAN interface needs a parent interface")
            vid = raw.get("vlan_id")
            if isinstance(vid, bool) or not isinstance(vid, int) or not 1 <= vid <= 4094:
                raise NetifError("a VLAN id must be a whole number from 1 to 4094")
            vlan_id = vid
            if not name:
                name = f"{parent}.{vid}"
                if len(name) > 15:
                    raise NetifError(
                        f"the derived name {name!r} is longer than the kernel's 15-character "
                        "limit — give the VLAN interface an explicit name"
                    )
            if (parent, vid) in vlans:
                raise NetifError(f"VLAN {vid} on {parent} is configured twice")
            vlans.add((parent, vid))
        elif raw.get("parent") or raw.get("vlan_id") is not None:
            raise NetifError(
                f"{name or 'an ethernet interface'}: parent and vlan_id apply to VLANs only"
            )
        if not _IFNAME_RE.match(name):
            raise NetifError(
                f"{name!r} is not a usable interface name — letters, digits, '.', '-' or '_', "
                "at most 15 characters"
            )
        if name in names:
            raise NetifError(f"{name} is configured twice")
        names.add(name)
        if kind == "vlan" and name == parent:
            raise NetifError(f"{name}: a VLAN cannot be its own parent")

        addr_in = raw.get("addresses") or []
        if not isinstance(addr_in, list):
            raise NetifError(f"{name}: addresses must be a list")
        if len(addr_in) > MAX_ADDRESSES:
            raise NetifError(f"{name}: at most {MAX_ADDRESSES} addresses per interface")
        addresses: list[str] = []
        for a in addr_in:
            norm = _validate_address(a, name)
            if norm in addresses:
                raise NetifError(f"{name}: {norm} is listed twice")
            addresses.append(norm)

        mtu = raw.get("mtu")
        if mtu is not None:
            if isinstance(mtu, bool) or not isinstance(mtu, int) or not 576 <= mtu <= 9216:
                raise NetifError(f"{name}: the MTU must be a whole number from 576 to 9216")
            if mtu < 1280 and any(ipaddress.ip_interface(a).version == 6 for a in addresses):
                raise NetifError(
                    f"{name}: an IPv6 address needs an MTU of at least 1280 (RFC 8200)"
                )

        up = raw.get("up", True)
        if not isinstance(up, bool):
            raise NetifError(f"{name}: 'up' must be true or false")

        routes_in = raw.get("routes") or []
        if not isinstance(routes_in, list):
            raise NetifError(f"{name}: routes must be a list")
        if len(routes_in) > MAX_ROUTES:
            raise NetifError(f"{name}: at most {MAX_ROUTES} routes per interface")
        routes: list[dict[str, Any]] = []
        seen_routes: set[tuple[str, int | None]] = set()
        for r in routes_in:
            nr = _validate_route(r, name, addresses)
            key = (nr["destination"], nr["metric"])
            if key in seen_routes:
                raise NetifError(f"{name}: the route to {nr['destination']} is listed twice")
            seen_routes.add(key)
            routes.append(nr)
        if routes and not up:
            raise NetifError(f"{name}: routes cannot be configured on an interface that is down")

        row: dict[str, Any] = {
            "name": name,
            "kind": kind,
            "parent": parent,
            "vlan_id": vlan_id,
            "addresses": addresses,
            "mtu": mtu,
            "up": up,
            "routes": routes,
        }
        desc = raw.get("description")
        if isinstance(desc, str) and desc.strip():
            # UI-only: never reaches the hash, so renaming a note does not
            # re-apply the interface.
            row["description"] = desc.strip()[:120]
        out.append(row)

    for row in out:
        if row["kind"] == "vlan":
            parent = row["parent"]
            sibling = next((r for r in out if r["name"] == parent), None)
            if sibling is not None and sibling["kind"] == "vlan":
                raise NetifError(f"{row['name']}: stacked VLANs (QinQ) are not supported")
    return out


# ── Validation against the node ──────────────────────────────────────


def _connected(row: dict[str, Any]) -> list[Any]:
    return [ipaddress.ip_interface(a).network for a in row["addresses"]]


def validate_desired(entries: Any, ctx: NetifContext) -> list[dict[str, Any]]:
    """The full check: shape, then everything that needs the node's inventory."""
    rows = normalise_desired(entries)
    by_name = {r["name"]: r for r in rows}

    for r in rows:
        name = r["name"]
        why = ctx.protected.get(name)
        if why:
            raise NetifError(
                f"{name} cannot be managed here: {why}. Changing it could cut the node "
                "off from the control plane."
            )
        if r["kind"] == "ethernet":
            kind = ctx.kinds.get(name)
            if kind is None:
                raise NetifError(f"{name}: the node does not report an interface with this name")
            if kind != "ethernet":
                raise NetifError(
                    f"{name} is a {kind} interface, not a physical NIC. Only ethernet ports "
                    "and VLANs on them can be managed here."
                )
            if name in ctx.masters:
                raise NetifError(
                    f"{name} is a member of {ctx.masters[name]} and cannot be addressed"
                )
        else:
            parent = r["parent"]
            in_doc = by_name.get(parent)
            if in_doc is None:
                pkind = ctx.kinds.get(parent)
                if pkind is None:
                    raise NetifError(
                        f"{name}: the parent {parent} does not exist on this node, and is not "
                        "configured in this change"
                    )
                if pkind not in VLAN_PARENT_KINDS:
                    raise NetifError(f"{name}: a VLAN cannot be stacked on a {pkind} interface")
            existing = ctx.kinds.get(name)
            if existing is not None and existing != "vlan":
                raise NetifError(f"{name} already exists on this node and is not a VLAN")
            live = ctx.vlans.get(name)
            if live is not None and live != (parent, r["vlan_id"]):
                raise NetifError(
                    f"{name} already exists on this node as VLAN {live[1]} on {live[0]}; "
                    "pick another name so the two are not confused"
                )
            parent_mtu = (in_doc or {}).get("mtu") or ctx.mtus.get(parent)
            if r["mtu"] is not None and parent_mtu is not None and r["mtu"] > parent_mtu:
                raise NetifError(
                    f"{name}: the MTU {r['mtu']} is larger than its parent {parent} ({parent_mtu})"
                )

    # Overlap between the interfaces in this change.
    for i, a in enumerate(rows):
        for b in rows[i + 1 :]:
            for na in _connected(a):
                for nb in _connected(b):
                    if _overlaps(na, nb):
                        raise NetifError(
                            f"{a['name']} ({na}) and {b['name']} ({nb}) have overlapping "
                            "subnets — the kernel could not tell which port reaches which"
                        )

    # Overlap with what the node already has.
    for r in rows:
        for net in _connected(r):
            for other, owner in ctx.foreign:
                if _overlaps(net, other):
                    raise NetifError(
                        f"{r['name']}: {net} overlaps {other} on {owner}, which this feature "
                        "does not manage"
                    )
            for other, label in ctx.reserved:
                if _overlaps(net, other):
                    raise NetifError(f"{r['name']}: {net} overlaps {label} ({other})")

    # Routes must not take over paths the node already depends on.
    for r in rows:
        for route in r["routes"]:
            dest = ipaddress.ip_network(route["destination"])
            for other, label in ctx.reserved:
                if _overlaps(dest, other):
                    raise NetifError(
                        f"{r['name']}: the route to {dest} would cover {label} ({other}) and "
                        "redirect cluster traffic through this interface"
                    )
            for other, owner in ctx.foreign:
                if (
                    owner in ctx.protected
                    and _overlaps(dest, other)
                    and dest.prefixlen <= other.prefixlen
                ):
                    raise NetifError(
                        f"{r['name']}: the route to {dest} would cover {other} on {owner}, "
                        "the node's management network"
                    )
            for other_row in rows:
                if other_row is r:
                    continue
                for net in _connected(other_row):
                    if _overlaps(dest, net) and dest.prefixlen <= net.prefixlen:
                        raise NetifError(
                            f"{r['name']}: the route to {dest} would shadow {net}, which is "
                            f"directly connected on {other_row['name']}"
                        )
    return rows


# ── Bundle for the heartbeat ──────────────────────────────────────────


def _wire(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out = []
    for r in sorted(rows, key=lambda x: x["name"]):
        out.append(
            {
                "name": r["name"],
                "kind": r["kind"],
                "parent": r["parent"],
                "vlan_id": r["vlan_id"],
                "addresses": list(r["addresses"]),
                "mtu": r["mtu"],
                "up": r["up"],
                "routes": sorted(
                    (
                        {
                            "destination": x["destination"],
                            "gateway": x["gateway"],
                            "metric": x["metric"],
                        }
                        for x in r["routes"]
                    ),
                    key=lambda x: (x["destination"], x["metric"] or 0),
                ),
            }
        )
    return out


def desired_hash(desired: Any) -> str:
    wire = _wire(normalise_desired(desired or []))
    body = json.dumps(wire, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(body.encode()).hexdigest()


def netif_bundle(desired: Any) -> dict[str, Any]:
    """The per-appliance heartbeat block the supervisor hashes + applies.

    Only the fields the host runner acts on reach the hash; the UI note
    does not. **An empty set hashes to a real digest, not ``""``**, for the
    reason ``removable_bundle`` documents at length: ``""`` is what a
    missing applied-hash sidecar reads as, and removal is an ordinary
    operator action on this plane.
    """
    wire = _wire(normalise_desired(desired or []))
    body = json.dumps(wire, sort_keys=True, separators=(",", ":"))
    return {
        "enabled": bool(wire),
        "config_hash": hashlib.sha256(body.encode()).hexdigest(),
        "interfaces": wire,
        "revert_seconds": REVERT_SECONDS,
    }


def netif_bundle_safe(desired: Any) -> dict[str, Any]:
    """``netif_bundle``, but never raising and never destructive.

    Rendered inside the heartbeat, which cannot 500. And it must NOT fall
    back to an empty list: on this plane an empty list is the instruction
    that tears every managed interface down, so a stored set that stops
    validating would silently cut the node off a VLAN. ``interfaces=None``
    is "no instruction" to the supervisor.
    """
    try:
        return netif_bundle(desired)
    except NetifError as exc:
        return {
            "enabled": False,
            "config_hash": "",
            "interfaces": None,
            "revert_seconds": REVERT_SECONDS,
            "error": str(exc),
        }


# ── Joining desired against reported ─────────────────────────────────


def apply_status(cluster_health: Any) -> dict[str, Any] | None:
    block = report(cluster_health)
    status = (block or {}).get("apply_status")
    return status if isinstance(status, dict) else None


def merge_state(desired: Any, cluster_health: Any) -> list[dict[str, Any]]:
    """Join the desired set with what the node reports (#4428).

    Each interface gets a ``state``:

    ``active``      applied and the node reports it up
    ``inactive``    applied but the link is down (no carrier, or ``up: false``)
    ``confirming``  applied; the node is waiting for the control plane to
                    confirm it can still be reached, and will roll back if not
    ``pending``     the node has not applied the current desired set yet
    ``reverted``    the node applied it, lost contact, and restored the
                    previous profiles — the desired set is NOT in force
    ``failed``      the runner refused or failed the apply
    ``unreported``  the node has not said
    """
    try:
        rows = normalise_desired(desired or [])
        current = desired_hash(desired or [])
    except NetifError:
        rows, current = [], ""
    block = report(cluster_health)
    status = apply_status(cluster_health)
    live = {n["name"]: n for n in inventory_nics(cluster_health) if n["name"]}
    per = (status or {}).get("interfaces")
    per = per if isinstance(per, dict) else {}
    out: list[dict[str, Any]] = []
    for r in rows:
        detail: str | None = None
        if block is None:
            state = "unreported"
        elif not status or status.get("hash") != current:
            # Not applied yet. A failure recorded against an OLDER hash is
            # not this config's failure, so it is not shown against it.
            state = "pending"
        else:
            applied = status.get("state")
            if applied == "reverted":
                state = "reverted"
                detail = _s(status.get("error"), 500) or None
            elif applied == "failed":
                state = "failed"
                detail = _s(status.get("error"), 500) or None
            elif applied == "pending-confirm":
                state = "confirming"
            else:
                verdict = _s(per.get(r["name"]), 200)
                nic = live.get(r["name"])
                if verdict.startswith("inactive"):
                    state, detail = "inactive", verdict.partition(":")[2].strip() or None
                elif nic is not None and nic["state"] == "up":
                    state = "active"
                elif not r["up"]:
                    state = "inactive"
                    detail = "configured down"
                else:
                    state = "inactive"
                    detail = "the link is down — no cable or no carrier"
        live_nic = live.get(r["name"])
        out.append(
            {
                **r,
                "state": state,
                "detail": detail,
                "live_addresses": (live_nic or {}).get("addresses", []),
                "live_state": (live_nic or {}).get("state"),
                "live_carrier": (live_nic or {}).get("carrier"),
            }
        )
    return out


__all__ = [
    "KINDS",
    "MAX_ADDRESSES",
    "MAX_INTERFACES",
    "MAX_ROUTES",
    "NetifContext",
    "NetifError",
    "REVERT_SECONDS",
    "apply_status",
    "build_context",
    "desired_hash",
    "has_inventory",
    "inventory_nics",
    "inventory_routes",
    "merge_state",
    "netif_bundle",
    "netif_bundle_safe",
    "nic_fields",
    "normalise_desired",
    "report",
    "route_fields",
    "validate_desired",
]
