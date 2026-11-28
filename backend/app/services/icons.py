"""Built-in icons on IP addresses and DNS records (#5022).

Three things live here:

* the **catalog** of icon names the API accepts, generated from the pinned
  ``@mdi/js`` package (``backend/app/data/mdi_icons.json``, regenerated with
  ``frontend/scripts/gen-mdi-icons.mjs``; a test fails when it lags the
  package-lock pin). A stored icon is ``mdi:<name>``; the namespace leaves room
  for other sets without a migration. A typo is a 422, never a blank cell.
* the **shipped default mapping** (device class, IP role, network device type
  -> icon), in code. An ``icon_default`` row exists only when an operator
  changed an entry, so a fresh install has none and a change to the shipped
  mapping reaches every install that never touched the entry.
* the **resolution**: explicit -> device-class default -> IP-role default for
  an address; explicit -> the linked address's effective icon for a DNS record.
  The server resolves so the web UI, the mobile app, API consumers and the
  Copilot all draw the same thing.
"""

from __future__ import annotations

import json
import re
import time
import uuid
from collections.abc import Iterable
from functools import lru_cache
from pathlib import Path
from typing import Any, Literal, NamedTuple

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

ICON_NAMESPACE = "mdi:"
DEFAULT_KINDS: tuple[str, ...] = ("device_class", "ip_role", "network_device_type")
IconSource = Literal["explicit", "device_class", "ip_role", "linked_ip", "none"]

_CATALOG_FILE = Path(__file__).resolve().parent.parent / "data" / "mdi_icons.json"


class CatalogEntry(NamedTuple):
    name: str  # namespaced, ``mdi:printer``
    label: str  # ``Printer``
    search: str  # lower-cased haystack: name + tags + aliases


@lru_cache(maxsize=1)
def _load_catalog() -> tuple[str, tuple[CatalogEntry, ...], frozenset[str]]:
    data = json.loads(_CATALOG_FILE.read_text(encoding="utf-8"))
    entries: list[CatalogEntry] = []
    for row in data["icons"]:
        name = row["name"]
        hay = " ".join([name.replace("-", " "), *row.get("tags", []), *row.get("aliases", [])])
        entries.append(
            CatalogEntry(
                f"{ICON_NAMESPACE}{name}",
                icon_label(f"{ICON_NAMESPACE}{name}"),
                hay.lower(),
            )
        )
    return data["version"], tuple(entries), frozenset(e.name for e in entries)


def catalog_version() -> str:
    return _load_catalog()[0]


def icon_label(icon: str) -> str:
    """Human label for ``mdi:router-wireless`` -> ``Router wireless``."""
    base = icon.removeprefix(ICON_NAMESPACE).replace("-", " ").strip()
    return base[:1].upper() + base[1:]


def is_valid_icon(icon: str) -> bool:
    return icon in _load_catalog()[2]


def validate_icon(value: Any) -> Any:
    """Field-validator body shared by every schema that takes an ``icon``.

    ``None`` and ``""`` clear the icon. A non-string is handed to core
    validation (a normal 422). Anything else must be a known ``mdi:`` name.
    """
    if value is None:
        return None
    if not isinstance(value, str):
        return value
    value = value.strip()
    if value == "":
        return None
    if not value.startswith(ICON_NAMESPACE):
        raise ValueError(f"icon must be a built-in icon named like '{ICON_NAMESPACE}printer'")
    if not is_valid_icon(value):
        raise ValueError(
            f"unknown icon {value!r}; list the built-in icons at GET /api/v1/icons/catalog"
        )
    return value


def search_catalog(query: str | None) -> list[CatalogEntry]:
    entries = _load_catalog()[1]
    if not query or not query.strip():
        return list(entries)
    terms = query.lower().split()
    hits = [e for e in entries if all(t in e.search for t in terms)]
    # Names that start with the first term come first, then the rest by name.
    first = terms[0]
    hits.sort(
        key=lambda e: (
            not e.name.removeprefix(ICON_NAMESPACE).startswith(first),
            first not in e.name,
            e.name,
        )
    )
    return hits


# ── Shipped default mapping ──────────────────────────────────────────────

# Device classes are free text from a lookup service, so keys are lower-cased
# and listed with the aliases of the common classes (Fingerbank top-level class
# names and the shorter names operators and the nmap profiler use). Unknown
# classes get no icon rather than a wrong one.
_DEVICE_CLASS_DEFAULTS: dict[str, str] = {
    "printer": "mdi:printer",
    "printers": "mdi:printer",
    "printer or scanner": "mdi:printer",
    "printer, scanner or fax": "mdi:printer",
    "scanner": "mdi:scanner",
    "3d printer": "mdi:printer-3d",
    "phone": "mdi:cellphone",
    "smartphone": "mdi:cellphone",
    "smartphones": "mdi:cellphone",
    "mobile": "mdi:cellphone",
    "phone, tablet or wearable": "mdi:cellphone",
    "phone, tablet, or wearable": "mdi:cellphone",
    "tablet": "mdi:tablet",
    "tablets": "mdi:tablet",
    "wearable": "mdi:watch",
    "voip": "mdi:phone-voip",
    "voip phone": "mdi:phone-voip",
    "voice over ip": "mdi:phone-voip",
    "ip phone": "mdi:phone-voip",
    "windows": "mdi:desktop-tower-monitor",
    "windows os": "mdi:desktop-tower-monitor",
    "macintosh": "mdi:laptop",
    "macintosh os": "mdi:laptop",
    "mac": "mdi:laptop",
    "macos": "mdi:laptop",
    "laptop": "mdi:laptop",
    "workstation": "mdi:desktop-tower-monitor",
    "desktop": "mdi:desktop-tower-monitor",
    "linux": "mdi:console",
    "linux os": "mdi:console",
    "unix": "mdi:console",
    "server": "mdi:server",
    "nas": "mdi:nas",
    "storage": "mdi:harddisk",
    "storage device": "mdi:harddisk",
    "storage devices": "mdi:harddisk",
    "router": "mdi:router-network",
    "router, access point or femtocell": "mdi:router-wireless",
    "access point": "mdi:access-point",
    "wireless access point": "mdi:access-point",
    "switch": "mdi:switch",
    "switching and wireless hardware": "mdi:switch",
    "firewall": "mdi:wall-fire",
    "iot": "mdi:home-automation",
    "internet of things (iot)": "mdi:home-automation",
    "internet of things": "mdi:home-automation",
    "home automation": "mdi:home-automation",
    "thermostat": "mdi:thermostat",
    "lighting": "mdi:lightbulb",
    "smart lock": "mdi:lock",
    "game console": "mdi:controller",
    "gaming console": "mdi:controller",
    "gaming": "mdi:controller",
    "video surveillance": "mdi:cctv",
    "surveillance": "mdi:cctv",
    "security camera": "mdi:cctv",
    "ip camera": "mdi:cctv",
    "camera": "mdi:camera",
    "tv": "mdi:television",
    "smart tv": "mdi:television",
    "television": "mdi:television",
    "audio, video and radio devices": "mdi:television",
    "audio, video, and radio devices": "mdi:television",
    "speaker": "mdi:speaker",
    "projector": "mdi:projector",
    "single board computer": "mdi:raspberry-pi",
    "raspberry pi": "mdi:raspberry-pi",
    "robot vacuum": "mdi:robot-vacuum",
}

_IP_ROLE_DEFAULTS: dict[str, str] = {
    "gateway": "mdi:router-network",
    "loopback": "mdi:repeat",
    "anycast": "mdi:broadcast",
    "vip": "mdi:ip-network",
    "vrrp": "mdi:shield-sync",
    "secondary": "mdi:plus-network",
    "bmc": "mdi:chip",
    "web": "mdi:web",
    "api": "mdi:api",
    "lb": "mdi:scale-balance",
}

_NETWORK_DEVICE_TYPE_DEFAULTS: dict[str, str] = {
    "router": "mdi:router-network",
    "switch": "mdi:switch",
    "l3_switch": "mdi:switch",
    "ap": "mdi:access-point",
    "firewall": "mdi:wall-fire",
    "other": "mdi:server-network",
}

SHIPPED_DEFAULTS: dict[str, dict[str, str]] = {
    "device_class": _DEVICE_CLASS_DEFAULTS,
    "ip_role": _IP_ROLE_DEFAULTS,
    "network_device_type": _NETWORK_DEVICE_TYPE_DEFAULTS,
}


def normalise_match(value: str | None) -> str:
    """Trim, lower-case and collapse whitespace, the key form of every mapping."""
    return re.sub(r"\s+", " ", (value or "").strip().lower())


# ── Operator overrides (in-memory) ───────────────────────────────────────

# ``(kind, match_value) -> icon`` for the rows operators changed. Read by the
# response validators, which are synchronous, so it is held in memory and
# refreshed by :func:`refresh_overrides` (one small query at most once per
# ``_OVERRIDES_TTL`` per process, and straight away after a local change).
_OVERRIDES_TTL = 10.0
_overrides: dict[tuple[str, str], str] = {}
_overrides_loaded_at: float = float("-inf")


def set_overrides(rows: Iterable[tuple[str, str, str]]) -> None:
    global _overrides, _overrides_loaded_at
    _overrides = {(k, m): i for k, m, i in rows}
    _overrides_loaded_at = time.monotonic()


def invalidate_overrides() -> None:
    global _overrides_loaded_at
    _overrides_loaded_at = float("-inf")


def reset_overrides() -> None:
    """Forget everything (tests)."""
    global _overrides
    _overrides = {}
    invalidate_overrides()


async def refresh_overrides(db: AsyncSession, *, force: bool = False) -> None:
    from app.models.icon import IconDefault

    if not force and time.monotonic() - _overrides_loaded_at < _OVERRIDES_TTL:
        return
    rows = (await db.execute(select(IconDefault))).scalars().all()
    set_overrides((r.kind, r.match_value, r.icon) for r in rows)


def default_icon_for(kind: str, value: str | None) -> str | None:
    key = normalise_match(value)
    if not key:
        return None
    override = _overrides.get((kind, key))
    if override is not None:
        return override
    return SHIPPED_DEFAULTS.get(kind, {}).get(key)


def default_mapping_rows() -> list[dict[str, Any]]:
    """Every effective mapping: shipped entries, overridden or not, plus the
    operator-added ones, ordered by kind then match value."""
    out: list[dict[str, Any]] = []
    for kind in DEFAULT_KINDS:
        shipped = SHIPPED_DEFAULTS[kind]
        keys = set(shipped) | {m for (k, m) in _overrides if k == kind}
        for match in sorted(keys):
            icon = _overrides.get((kind, match)) or shipped[match]
            out.append(
                {
                    "kind": kind,
                    "match_value": match,
                    "icon": icon,
                    "default_icon": shipped.get(match),
                    "overridden": (kind, match) in _overrides,
                }
            )
    return out


# ── Resolution ───────────────────────────────────────────────────────────


class ResolvedIcon(NamedTuple):
    icon: str | None
    source: IconSource


NO_ICON = ResolvedIcon(None, "none")


def resolve_ip_icon(
    *,
    icon: str | None,
    device_class: str | None,
    device_type: str | None,
    role: str | None,
) -> ResolvedIcon:
    """Explicit, then the device-class default (the class, then the type), then
    the IP-role default. An ordinary host (no role) with an unknown device class
    gets no icon rather than a generic placeholder."""
    if icon:
        return ResolvedIcon(icon, "explicit")
    for candidate in (device_class, device_type):
        found = default_icon_for("device_class", candidate)
        if found:
            return ResolvedIcon(found, "device_class")
    found = default_icon_for("ip_role", role)
    if found:
        return ResolvedIcon(found, "ip_role")
    return NO_ICON


def resolve_record_icon(*, icon: str | None, linked: ResolvedIcon | None) -> ResolvedIcon:
    """Explicit, then the linked IPAM address's effective icon. Record types get
    no default of their own: the type badge already says it."""
    if icon:
        return ResolvedIcon(icon, "explicit")
    if linked is not None and linked.icon:
        return ResolvedIcon(linked.icon, "linked_ip")
    return NO_ICON


async def attach_record_icons(db: AsyncSession, records: Iterable[Any]) -> None:
    """Set ``effective_icon`` / ``icon_source`` on DNS record rows, for the
    response schema to read. One query for every linked address on the page
    (none when no row needs one); an address whose subnet is in the Trash does
    not feed a live record."""
    from app.models.ipam import IPAddress
    from app.services.ipam.live_address import live_subnet_clause

    rows = list(records)
    link_ids = {r.ip_address_id for r in rows if not r.icon and r.ip_address_id is not None}
    linked: dict[uuid.UUID, ResolvedIcon] = {}
    if link_ids:
        found = await db.execute(
            select(
                IPAddress.id,
                IPAddress.icon,
                IPAddress.device_class,
                IPAddress.device_type,
                IPAddress.role,
            ).where(IPAddress.id.in_(link_ids), live_subnet_clause())
        )
        for ip_id, icon, device_class, device_type, role in found.all():
            linked[ip_id] = resolve_ip_icon(
                icon=icon, device_class=device_class, device_type=device_type, role=role
            )
    for r in rows:
        resolved = resolve_record_icon(
            icon=r.icon, linked=linked.get(r.ip_address_id) if r.ip_address_id else None
        )
        r.effective_icon = resolved.icon
        r.icon_source = resolved.source
