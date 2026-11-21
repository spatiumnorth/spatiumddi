"""FortiGate DHCP driver (agentless, FortiOS REST API + API token).

FortiGate firewalls run a per-interface DHCP server. SpatiumDDI manages
them agentlessly: the control plane calls the FortiOS REST API directly
with an API-admin **Bearer token**, VDOM-scoped, rather than driving a
co-located agent (see :mod:`app.drivers.dhcp._cloud_base` for the
agentless contract).

**Model mapping** (one SpatiumDDI ``DHCPServer(driver="fortigate")`` per
FortiGate device + VDOM):

* A SpatiumDDI ``DHCPScope`` (one subnet) maps to the FortiGate
  ``system.dhcp.server`` object on the **interface whose primary IP+netmask
  CIDR equals the scope CIDR**. We match on CIDR and configure that
  interface's DHCP server — we never create interfaces or change interface
  IPs. No matching interface → the apply fails with a clear error;
  multiple matches → an ambiguity error.
* Dynamic pools → ``ip-range`` entries (FortiGate supports several).
* ``excluded`` + ``reserved`` pools → ``exclude-range`` entries.
* Static assignments (MAC → IP) → ``reserved-address`` entries.
* Scope options → first-class fields where FortiGate has them
  (``default-gateway`` / ``dns-server1..4`` / ``domain`` / ``ntp-server1..3``
  / ``filename`` / ``lease-time``), the generic ``options`` subtable
  otherwise. ``netmask`` is always derived from the subnet CIDR.

The write unit is the **whole DHCP-server object per scope**: any
scope/pool/static/option edit rebuilds the full desired object and PUTs it
(create-if-absent). The interface name is the natural key — one DHCP server
per interface. FortiOS applies a parent PUT to child tables **per entry
id**, not as an atomic replace, so before an update PUT the driver pins
each child entry to the id it already holds on the device and issues
explicit child-endpoint DELETEs for removed entries (see
``_reconcile_child_ids``) — without that, deleting a non-last reservation
renumbers the table mid-apply and FortiOS aborts partway, scrambling it.

**Ownership (#630).** So the driver never silently overwrites or deletes a
DHCP server the operator hand-managed on the FortiGate, the control plane
records the FortiOS ``mkey`` of the object *SpatiumDDI created* on the scope
(``DHCPScope.provider_refs``) and passes it back in as ``provider_ref``. On a
push: if we hold the mkey, PUT it; if we hold none and the interface is empty,
POST and record the new mkey; if we hold none but an object already exists, we
:class:`~app.drivers.dhcp._cloud_base.CloudDHCPAdoptionError` (→ 409) unless the
operator opts in via ``adopt_existing``. Removal only deletes an object we own.

Credential dict shape (Fernet-encrypted on ``DHCPServer.credentials_encrypted``)::

    {"api_token": "<api-admin-token>", "vdom": "root",
     "verify_tls": true, "ca_bundle_pem": "<optional PEM>"}

``verify_tls`` defaults to ``True`` — the FortiOS admin Bearer token is
sensitive, so we verify the TLS chain by default (matching the sibling
``services.fortinet.client.FortinetClient``). A WARNING is logged only when
an operator explicitly opts out. ``ca_bundle_pem`` lets a private-CA
FortiGate be pinned without disabling verification.
"""

from __future__ import annotations

import ipaddress
import ssl
from datetime import UTC, datetime
from typing import Any

import httpx
import structlog

from app.drivers.dhcp._cloud_base import (
    AgentlessDHCPDriverBase,
    CloudDHCPAdoptionError,
    CloudDHCPError,
    CloudDHCPProbe,
)
from app.drivers.dhcp.base import ScopeDef

logger = structlog.get_logger(__name__)


# Canonical SpatiumDDI option name → FortiGate DHCP option code, for the
# options SpatiumDDI models that FortiGate has no dedicated field for.
# ``routers`` / ``dns-servers`` / ``domain-name`` / ``ntp-servers`` /
# ``bootfile-name`` are handled as first-class fields, so they're absent
# here.
_OPTION_NAME_TO_CODE: dict[str, int] = {
    "time-offset": 2,
    "mtu": 26,
    "tftp-server-name": 66,
    "domain-search": 119,
    "tftp-server-address": 150,
}

# Numeric DHCP options carry a binary integer on the wire, NOT ASCII text, so
# FortiGate must send them as ``type: "hex"`` (big-endian) — a ``type: "string"``
# "1500" reaches the client as the literal characters, not the 16-bit MTU. Maps
# code → (byte width, signed). ``time-offset`` (2) is a signed 32-bit seconds
# offset; ``mtu`` (26) is an unsigned 16-bit size.
_NUMERIC_OPTION_ENCODING: dict[int, tuple[int, bool]] = {
    2: (4, True),
    26: (2, False),
}

# Option names FortiGate derives itself / that map to a first-class field,
# so they never go into the generic ``options`` subtable.
_OPTIONS_HANDLED_ELSEWHERE: frozenset[str] = frozenset(
    {
        "routers",
        "dns-servers",
        "domain-name",
        "ntp-servers",
        "bootfile-name",
        "broadcast-address",
    }
)

# Child tables of ``system.dhcp.server`` whose entry ``id``s must stay STABLE
# across pushes, mapped to the content key that identifies an entry across
# renumbering. FortiOS applies a parent PUT per child ``id`` — it is not an
# atomic replace — so if a delete shifts every later entry down one id, the
# update of id k to id k+1's old content transiently collides with the entry
# still sitting at id k+1 (duplicate MAC / overlapping range), FortiOS aborts
# partway, and the table is left scrambled: the *wrong* reservations vanish
# and the API returns an error. Keying each entry to the id it already holds
# on the device makes every push a pure per-entry upsert; removals are issued
# as explicit child-endpoint DELETEs (see ``_reconcile_child_ids``).
_CHILD_TABLE_KEYS: dict[str, Any] = {
    "reserved-address": lambda e: _norm_mac(e.get("mac")),
    "ip-range": lambda e: (str(e.get("start-ip") or ""), str(e.get("end-ip") or "")),
    "exclude-range": lambda e: (str(e.get("start-ip") or ""), str(e.get("end-ip") or "")),
    "options": lambda e: e.get("code"),
}

# Stale-entry deletes run in this order so no transient state violates a
# FortiOS cross-table constraint (an exclude-range must lie within an
# ip-range, so excludes go before the ranges they depend on).
_CHILD_TABLE_DELETE_ORDER: tuple[str, ...] = (
    "exclude-range",
    "reserved-address",
    "options",
    "ip-range",
)


def _norm_mac(value: Any) -> str:
    """Canonicalise a MAC for cross-system comparison (lowercase, no separators)."""
    return "".join(c for c in str(value or "").lower() if c in "0123456789abcdef")


def _as_list(value: Any) -> list[str]:
    """Normalise an option value (str / list / comma|space-separated) to a
    list of trimmed non-empty strings."""
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        items = [str(v).strip() for v in value]
    else:
        items = [p.strip() for p in str(value).replace(",", " ").split()]
    return [i for i in items if i]


def _ip_int(value: Any) -> int | None:
    """Parse an IPv4 string to its integer form, or None if invalid."""
    try:
        return int(ipaddress.IPv4Address(str(value)))
    except (ipaddress.AddressValueError, ValueError):
        return None


def _int_ip(value: int) -> str:
    """Render an integer back to dotted-quad IPv4."""
    return str(ipaddress.IPv4Address(value))


def _all_ips(values: list[str]) -> bool:
    """True when every value parses as an IP address."""
    if not values:
        return False
    for v in values:
        try:
            ipaddress.ip_address(v)
        except ValueError:
            return False
    return True


class FortiGateDHCPDriver(AgentlessDHCPDriverBase):
    """Agentless driver for FortiGate per-interface DHCP servers."""

    name = "fortigate"
    # The create modal renders + the probe requires these. ``verify_tls``
    # is a bool checkbox (default on); ``vdom`` defaults to ``root`` in the
    # UI; ``ca_bundle_pem`` is an optional PEM for private-CA FortiGates.
    credential_fields: tuple[str, ...] = (
        "api_token",
        "vdom",
        "verify_tls",
        "ca_bundle_pem",
    )

    # ── HTTP plumbing ───────────────────────────────────────────────────
    def _client(self, server: Any, creds: dict[str, Any]) -> httpx.AsyncClient:
        """Return an httpx client bound to the FortiGate REST API base.

        Single seam tests patch to inject a fake transport — keep every
        request flowing through the returned client. The API token rides
        in the Authorization header (never the URL) and the VDOM is a
        default query param on every call.
        """
        token = self._token(creds)
        host = getattr(server, "host", "") or ""
        port = int(getattr(server, "port", 443) or 443)
        vdom = str(creds.get("vdom") or "root")
        verify = self._build_verify(
            bool(creds.get("verify_tls", True)),
            str(creds.get("ca_bundle_pem") or ""),
            server=str(getattr(server, "id", "")),
            host=host,
        )
        return httpx.AsyncClient(
            base_url=f"https://{host}:{port}/api/v2",
            headers={"Authorization": f"Bearer {token}"},
            params={"vdom": vdom},
            verify=verify,
            timeout=30.0,
        )

    @staticmethod
    def _build_verify(verify_tls: bool, ca_bundle_pem: str, *, server: str, host: str) -> Any:
        """httpx ``verify`` value: ``False`` when opted out (with a WARNING),
        a CA-pinned SSL context when a PEM bundle is supplied, else ``True``
        for the system trust store. Mirrors
        ``services.fortinet.client.FortinetClient._build_verify``."""
        if not verify_tls:
            logger.warning("fortigate.tls_verification_disabled", server=server, host=host)
            return False
        ca = (ca_bundle_pem or "").strip()
        if ca:
            return ssl.create_default_context(cadata=ca)
        return True

    @staticmethod
    def _token(creds: dict[str, Any]) -> str:
        token = (creds or {}).get("api_token")
        if not token:
            raise CloudDHCPError("FortiGate credentials missing 'api_token'.")
        return str(token)

    @staticmethod
    def _unwrap(response: httpx.Response) -> dict[str, Any]:
        """Validate a FortiOS response and return its parsed body.

        FortiOS returns ``{"http_status": 200, "status": "success",
        "results": [...], "mkey": <n>}`` on success and a non-2xx status
        (or ``status: "error"``) on failure. Raise :class:`CloudDHCPError`
        with the FortiOS error code / http status so the write-through
        surfaces a clean 502.
        """
        try:
            body = response.json()
        except (ValueError, TypeError):
            body = {}
        status = response.status_code
        api_status = str(body.get("status", "")) if isinstance(body, dict) else ""
        if 200 <= status < 300 and api_status in ("", "success"):
            return body if isinstance(body, dict) else {"results": body}
        err = ""
        if isinstance(body, dict):
            err = str(body.get("error") or body.get("cli_error") or body.get("message") or "")
        detail = f"HTTP {status}" + (f" (error {err})" if err else "")
        raise CloudDHCPError(f"FortiGate API error: {detail}")

    # ── Interface matching ──────────────────────────────────────────────
    async def _list_interface_cidrs(self, client: httpx.AsyncClient) -> list[dict[str, Any]]:
        """Return ``[{name, cidr, ip, netmask, status}]`` for L3 interfaces.

        Only the interface's PRIMARY IP is considered (per plan) — secondary
        IPs are ignored. Interfaces with no IP (``0.0.0.0``) are dropped.
        """
        resp = await client.get("/cmdb/system/interface")
        body = self._unwrap(resp)
        out: list[dict[str, Any]] = []
        for iface in body.get("results") or []:
            name = iface.get("name")
            addr, mask = self._parse_iface_ip(iface.get("ip"))
            if not name or not addr or addr == "0.0.0.0" or not mask:
                continue
            try:
                net = ipaddress.ip_network(f"{addr}/{mask}", strict=False)
            except (ValueError, TypeError):
                continue
            out.append(
                {
                    "name": name,
                    "cidr": str(net),
                    "ip": addr,
                    "netmask": mask,
                    "status": iface.get("status") or "",
                    "alias": iface.get("alias") or "",
                }
            )
        return out

    @staticmethod
    def _parse_iface_ip(raw: Any) -> tuple[str, str]:
        """Parse a FortiOS interface ``ip`` field into ``(addr, netmask)``.

        FortiOS returns this either as a 2-element list ``["1.2.3.4",
        "255.255.255.0"]`` or a space-separated string ``"1.2.3.4
        255.255.255.0"`` depending on version. Handle both.
        """
        if isinstance(raw, (list, tuple)) and len(raw) >= 2:
            return str(raw[0]).strip(), str(raw[1]).strip()
        if isinstance(raw, str):
            parts = raw.split()
            if len(parts) >= 2:
                return parts[0].strip(), parts[1].strip()
        return "", ""

    async def _match_interface(self, client: httpx.AsyncClient, subnet_cidr: str) -> str:
        """Return the name of the interface whose primary CIDR == ``subnet_cidr``.

        Raises :class:`CloudDHCPError` on no match / ambiguous match so the
        write-through rolls back with a clear 502.
        """
        try:
            target = ipaddress.ip_network(subnet_cidr, strict=False)
        except (ValueError, TypeError) as exc:
            raise CloudDHCPError(f"Scope CIDR {subnet_cidr!r} is not a valid network") from exc
        matches = [
            iface["name"]
            for iface in await self._list_interface_cidrs(client)
            if ipaddress.ip_network(iface["cidr"], strict=False) == target
        ]
        if not matches:
            raise CloudDHCPError(
                f"No FortiGate interface has an IP in {subnet_cidr}. Configure the "
                "interface IP/netmask on the FortiGate first, then retry."
            )
        if len(matches) > 1:
            raise CloudDHCPError(
                f"Multiple FortiGate interfaces match {subnet_cidr} "
                f"({', '.join(matches)}); cannot decide which to configure."
            )
        return matches[0]

    # ── DHCP-server object body ─────────────────────────────────────────
    def _build_server_body(self, interface: str, scope: ScopeDef) -> dict[str, Any]:
        """Render the full ``system.dhcp.server`` object body for ``scope``."""
        net = ipaddress.ip_network(scope.subnet_cidr, strict=False)
        opts = scope.options or {}

        body: dict[str, Any] = {
            "status": "enable" if scope.is_active else "disable",
            "interface": interface,
            "netmask": str(net.netmask),
            "lease-time": int(scope.lease_time or 0),
        }

        # First-class scalar fields are ALWAYS emitted (clearing to their
        # "unset" value when the option is absent) so a whole-object PUT
        # achieves replace-all for scalars too — otherwise an option removed
        # in SpatiumDDI would linger on the FortiGate.

        # default-gateway ← routers (first entry only; FortiGate has one).
        routers = _as_list(opts.get("routers"))
        body["default-gateway"] = routers[0] if routers else "0.0.0.0"

        # DNS ← dns-servers (4 dedicated slots). Absent → dns-service default
        # and all slots cleared.
        dns = _as_list(opts.get("dns-servers"))
        body["dns-service"] = "specify" if dns else "default"
        for i in range(1, 5):
            body[f"dns-server{i}"] = dns[i - 1] if i <= len(dns) else "0.0.0.0"

        # domain ← domain-name (scalar). FortiGate rejects an EMPTY domain
        # ("not a valid domain name", error -651), so — unlike the other
        # scalars — it can't be cleared via the API. We only set it when
        # present; removing the domain-name option in SpatiumDDI leaves the
        # last-set domain on the FortiGate (documented caveat).
        domain = _as_list(opts.get("domain-name"))
        if domain:
            body["domain"] = domain[0]

        # NTP ← ntp-servers (3 dedicated slots).
        ntp = _as_list(opts.get("ntp-servers"))
        body["ntp-service"] = "specify" if ntp else "default"
        for i in range(1, 4):
            body[f"ntp-server{i}"] = ntp[i - 1] if i <= len(ntp) else "0.0.0.0"

        # bootfile-name ← filename (scalar).
        bootfile = _as_list(opts.get("bootfile-name"))
        body["filename"] = bootfile[0] if bootfile else ""

        # ip-range ← dynamic pools; exclude-range ← excluded/reserved pools.
        #
        # FortiGate requires every ``exclude-range`` to fall WITHIN a
        # ``ip-range`` (an out-of-range exclude is rejected with FortiOS
        # error -40, verified live on 7.4.12). Excluding addresses the pool
        # never hands out is a no-op anyway, so we clip each excluded/reserved
        # pool to its intersection with the dynamic range(s) and drop any
        # portion that falls outside.
        dyn: list[tuple[int, int]] = []
        ip_ranges: list[dict[str, Any]] = []
        for pool in scope.pools:
            if pool.pool_type != "dynamic":
                continue
            s, e = _ip_int(pool.start_ip), _ip_int(pool.end_ip)
            if s is None or e is None:
                continue
            dyn.append((s, e))
            ip_ranges.append(
                {
                    "id": len(ip_ranges) + 1,
                    "start-ip": str(pool.start_ip),
                    "end-ip": str(pool.end_ip),
                }
            )
        exclude_ranges: list[dict[str, Any]] = []
        for pool in scope.pools:
            if pool.pool_type not in ("excluded", "reserved"):
                continue
            ps, pe = _ip_int(pool.start_ip), _ip_int(pool.end_ip)
            if ps is None or pe is None:
                continue
            for ds, de in dyn:
                lo, hi = max(ps, ds), min(pe, de)
                if lo <= hi:
                    exclude_ranges.append(
                        {
                            "id": len(exclude_ranges) + 1,
                            "start-ip": _int_ip(lo),
                            "end-ip": _int_ip(hi),
                        }
                    )
            if not any(max(ps, ds) <= min(pe, de) for ds, de in dyn):
                logger.warning(
                    "fortigate.exclude_range_outside_pool_dropped",
                    subnet=scope.subnet_cidr,
                    start=str(pool.start_ip),
                    end=str(pool.end_ip),
                )
        body["ip-range"] = ip_ranges
        body["exclude-range"] = exclude_ranges

        # reserved-address ← static assignments (MAC → IP).
        #
        # NOTE: do NOT send ``action: "assign"`` — on FortiOS 7.4.x it makes
        # the API silently store the reserved ``ip`` as ``0.0.0.0`` (verified
        # live on 7.4.12; a ``{type, ip, mac}`` body stores the IP correctly,
        # adding ``action`` zeroes it). ``assign`` is the default action
        # anyway, so omitting it yields the intended reservation.
        #
        # The positional ids assigned here are provisional: before an update
        # PUT, ``_reconcile_child_ids`` rewrites them to match the ids already
        # on the device (keyed by MAC) and issues explicit deletes for removed
        # entries — FortiOS applies a parent PUT per child id, not as an
        # atomic table replace, so shifting ids on a delete scrambles the
        # table (see ``_CHILD_TABLE_KEYS``).
        reserved: list[dict[str, Any]] = []
        for i, st in enumerate([x for x in scope.statics if x.mac_address is not None], start=1):
            reserved.append(
                {
                    "id": i,
                    "type": "mac",
                    "ip": str(st.ip_address),
                    "mac": str(st.mac_address),
                    "description": st.hostname or "",
                }
            )
        body["reserved-address"] = reserved

        # Generic options subtable ← everything not handled as a field.
        body["options"] = self._build_options(opts)
        return body

    def _build_options(self, opts: dict[str, Any]) -> list[dict[str, Any]]:
        """Render the generic ``options`` subtable for non-first-class options.

        Handles canonical names via :data:`_OPTION_NAME_TO_CODE` and
        ``code:NN`` custom keys. FortiGate ``options`` items carry ``code``,
        ``type`` (ip | string), and either ``ip`` (space-joined) or
        ``value``.
        """
        out: list[dict[str, Any]] = []
        for name, raw in (opts or {}).items():
            if name in _OPTIONS_HANDLED_ELSEWHERE:
                continue
            code: int | None
            if name in _OPTION_NAME_TO_CODE:
                code = _OPTION_NAME_TO_CODE[name]
            elif name.startswith("code:"):
                try:
                    code = int(name.split(":", 1)[1])
                except (ValueError, IndexError):
                    continue
            else:
                # Unknown / unmappable option name — skip rather than guess.
                continue
            values = _as_list(raw)
            if not values:
                continue
            item: dict[str, Any] = {"id": len(out) + 1, "code": code}
            hex_val = self._numeric_option_hex(code, values)
            if hex_val is not None:
                item["type"] = "hex"
                item["hex"] = hex_val
            elif _all_ips(values):
                item["type"] = "ip"
                item["ip"] = " ".join(values)
            else:
                item["type"] = "string"
                item["value"] = " ".join(values)
            out.append(item)
        return out

    @staticmethod
    def _numeric_option_hex(code: int, values: list[str]) -> str | None:
        """Big-endian hex for a numeric option (``mtu`` / ``time-offset``), or
        None if this option isn't numeric or the value doesn't fit its width."""
        enc = _NUMERIC_OPTION_ENCODING.get(code)
        if enc is None or len(values) != 1:
            return None
        width, signed = enc
        try:
            n = int(str(values[0]).strip())
            return n.to_bytes(width, "big", signed=signed).hex()
        except (ValueError, OverflowError):
            # Not an integer / out of range → fall back to string encoding.
            return None

    # ── Provider hooks (whole-scope write, lease read, probe) ───────────
    async def _find_server(
        self, client: httpx.AsyncClient, interface: str
    ) -> dict[str, Any] | None:
        """Return the raw ``system.dhcp.server`` object on ``interface``, or None."""
        resp = await client.get("/cmdb/system.dhcp/server")
        body = self._unwrap(resp)
        for srv in body.get("results") or []:
            if srv.get("interface") == interface:
                return srv if isinstance(srv, dict) else None
        return None

    @staticmethod
    def _coerce_mkey(raw: Any) -> int | None:
        """Best-effort int() of a FortiOS mkey field; None on missing/garbage."""
        if raw is None:
            return None
        try:
            return int(raw)
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _mkey_of(provider_ref: dict[str, Any] | None) -> int | None:
        if not provider_ref:
            return None
        try:
            return int(provider_ref["mkey"])
        except (KeyError, TypeError, ValueError):
            return None

    async def _apply_scope(
        self,
        server: Any,
        creds: dict[str, Any],
        scope: ScopeDef,
        *,
        provider_ref: dict[str, Any] | None = None,
        adopt_existing: bool = False,
    ) -> dict[str, Any] | None:
        async with self._client(server, creds) as client:
            interface = await self._match_interface(client, scope.subnet_cidr)
            body = self._build_server_body(interface, scope)
            existing = await self._find_server(client, interface)
            existing_id = self._coerce_mkey(existing.get("id")) if existing else None
            owned_mkey = self._mkey_of(provider_ref)

            if owned_mkey is not None:
                # This scope+server already owns an object on this interface.
                # Overwriting it is safe. If it was deleted out from under us,
                # recreate; otherwise PUT the object that's actually there.
                if existing_id is None or existing is None:
                    resp = await client.post("/cmdb/system.dhcp/server", json=body)
                    new_id = self._new_mkey(resp)
                    return {"mkey": new_id, "interface": interface}
                await self._reconcile_child_ids(client, existing_id, existing, body)
                resp = await client.put(f"/cmdb/system.dhcp/server/{existing_id}", json=body)
                self._unwrap(resp)
                return {"mkey": existing_id, "interface": interface}

            # We hold no ownership marker for this interface.
            if existing_id is None or existing is None:
                # Nothing here — create it and claim ownership.
                resp = await client.post("/cmdb/system.dhcp/server", json=body)
                new_id = self._new_mkey(resp)
                return {"mkey": new_id, "interface": interface}

            # An object exists that we never created. Refuse to clobber it
            # unless the operator explicitly opted in to adopt.
            if not adopt_existing:
                raise CloudDHCPAdoptionError(
                    f"A DHCP server already exists on FortiGate interface "
                    f"{interface!r} that SpatiumDDI did not create. Enable "
                    f"'adopt existing' to overwrite it with the managed scope, "
                    f"or remove it on the FortiGate first."
                )
            logger.info(
                "fortigate.adopt_existing_dhcp_server",
                server=str(getattr(server, "id", "")),
                interface=interface,
                mkey=existing_id,
            )
            await self._reconcile_child_ids(client, existing_id, existing, body)
            resp = await client.put(f"/cmdb/system.dhcp/server/{existing_id}", json=body)
            self._unwrap(resp)
            return {"mkey": existing_id, "interface": interface}

    async def _reconcile_child_ids(
        self,
        client: httpx.AsyncClient,
        mkey: int,
        existing: dict[str, Any],
        body: dict[str, Any],
    ) -> None:
        """Make an update PUT safe: stable child ids + explicit stale deletes.

        FortiOS applies a parent PUT to each child table **per entry id**, not
        as an atomic replace. The positional ids ``_build_server_body`` assigns
        therefore break deletion: removing a non-last entry shifts every later
        entry onto a different id, the per-id update transiently duplicates a
        MAC (or overlaps a range) that still exists at the next id, and FortiOS
        aborts mid-apply — the wrong entries end up deleted and the API errors
        out. (Observed live on 7.4.x; deleting the highest-id entry shifts
        nothing, which is why it only failed *sometimes*.)

        For each managed child table this rewrites the desired entries' ids to
        the id the same logical entry (matched by ``_CHILD_TABLE_KEYS``)
        already holds on the device, assigns fresh ids above every id in play
        to genuinely new entries, and explicitly ``DELETE``s device entries
        that are no longer desired via the child endpoint — which removes them
        correctly regardless of whether the firmware treats the parent PUT as
        replace or merge. A failed stale delete with FortiOS "entry not found"
        (HTTP 404) is tolerated as already-gone.
        """
        for table in _CHILD_TABLE_DELETE_ORDER:
            key_of = _CHILD_TABLE_KEYS[table]
            current = [e for e in (existing.get(table) or []) if isinstance(e, dict)]
            desired = list(body.get(table) or [])

            current_by_key: dict[Any, int] = {}
            for entry in current:
                cur_id = self._coerce_mkey(entry.get("id"))
                if cur_id is None:
                    continue
                # Duplicate keys on the device (residue of a previously
                # scrambled table) — keep the first, the rest become stale.
                current_by_key.setdefault(key_of(entry), cur_id)

            used_ids = {
                cur_id
                for entry in current
                if (cur_id := self._coerce_mkey(entry.get("id"))) is not None
            }
            kept_ids: set[int] = set()
            next_id = max(used_ids, default=0)
            for entry in desired:
                cur_id = current_by_key.get(key_of(entry))
                if cur_id is not None and cur_id not in kept_ids:
                    entry["id"] = cur_id
                    kept_ids.add(cur_id)
                else:
                    next_id += 1
                    entry["id"] = next_id

            for stale_id in sorted(used_ids - kept_ids):
                resp = await client.delete(f"/cmdb/system.dhcp/server/{mkey}/{table}/{stale_id}")
                if resp.status_code != 404:
                    self._unwrap(resp)

    def _new_mkey(self, resp: httpx.Response) -> int | None:
        """Extract the mkey FortiOS assigned to a freshly-POSTed object."""
        body = self._unwrap(resp)
        return self._coerce_mkey(body.get("mkey"))

    async def _remove_scope(
        self,
        server: Any,
        creds: dict[str, Any],
        subnet_cidr: str,
        *,
        provider_ref: dict[str, Any] | None = None,
    ) -> None:
        owned_mkey = self._mkey_of(provider_ref)
        if owned_mkey is None:
            # We never created an object here — leave any operator-managed DHCP
            # server on the interface untouched. Idempotent no-op.
            logger.info(
                "fortigate.remove_scope_skipped_unowned",
                server=str(getattr(server, "id", "")),
                subnet=subnet_cidr,
            )
            return
        async with self._client(server, creds) as client:
            resp = await client.delete(f"/cmdb/system.dhcp/server/{owned_mkey}")
            # A 404 (already gone) is fine — the object we owned is absent.
            if resp.status_code != 404:
                self._unwrap(resp)

    async def _get_leases(self, server: Any, creds: dict[str, Any]) -> list[dict[str, Any]]:
        async with self._client(server, creds) as client:
            resp = await client.get("/monitor/system/dhcp")
            body = self._unwrap(resp)
        out: list[dict[str, Any]] = []
        for lease in body.get("results") or []:
            if str(lease.get("type") or "ipv4") != "ipv4":
                continue
            ip = lease.get("ip")
            mac = lease.get("mac")
            if not ip or not mac:
                continue
            # FortiGate reports "leased" / "reserved" (and sometimes others).
            status = str(lease.get("status") or "").lower()
            if status and status not in ("leased", "reserved"):
                continue
            out.append(
                {
                    "ip_address": str(ip),
                    "mac_address": str(mac),
                    "hostname": lease.get("hostname") or None,
                    "client_id": None,
                    "state": "active",
                    "expires_at": _epoch_to_dt(lease.get("expire_time")),
                }
            )
        return out

    async def _probe(self, server: Any, creds: dict[str, Any]) -> CloudDHCPProbe:
        async with self._client(server, creds) as client:
            interfaces = await self._list_interface_cidrs(client)
        return CloudDHCPProbe(
            ok=True,
            message=f"Authenticated; {len(interfaces)} L3 interface(s) with an IP visible.",
            interface_count=len(interfaces),
        )

    async def list_interfaces(self, server: Any) -> list[dict[str, Any]]:
        """Preflight helper — list L3 interfaces + their CIDRs for the UI.

        Each interface is annotated with ``existing_dhcp_server`` (or ``None``)
        so the operator can see a pre-existing DHCP server — and its ip-range /
        reservation / option counts — that a sync would otherwise adopt.
        """
        creds = self._load_credentials(server)
        async with self._client(server, creds) as client:
            interfaces = await self._list_interface_cidrs(client)
            resp = await client.get("/cmdb/system.dhcp/server")
            body = self._unwrap(resp)
        by_iface: dict[str, dict[str, Any]] = {}
        for srv in body.get("results") or []:
            if not isinstance(srv, dict):
                continue
            iface = srv.get("interface")
            if not iface:
                continue
            mkey = self._coerce_mkey(srv.get("id"))
            by_iface[str(iface)] = {
                "mkey": mkey,
                "ip_range_count": len(srv.get("ip-range") or []),
                "reserved_count": len(srv.get("reserved-address") or []),
                "option_count": len(srv.get("options") or []),
            }
        for iface in interfaces:
            iface["existing_dhcp_server"] = by_iface.get(str(iface.get("name")))
        return interfaces

    # ── Capabilities ────────────────────────────────────────────────────
    def capabilities(self) -> dict[str, Any]:
        return {
            "name": "fortigate",
            "read_only": False,
            "bundle_config_push": False,
            "lease_monitoring": True,
            "scope_management": True,
            "reservation_management": True,
            "exclusion_management": True,
            "address_families": ["ipv4"],
            "transport": "https",
            "notes": (
                "Agentless FortiGate DHCP driver over the FortiOS REST API "
                "(Bearer API token, VDOM-scoped). Each subnet maps to the "
                "system.dhcp.server object on the interface whose CIDR "
                "matches; SpatiumDDI is the source of truth (push-only)."
            ),
        }


def _epoch_to_dt(value: Any) -> datetime | None:
    """Convert a FortiOS ``expire_time`` unix epoch (seconds) to a UTC dt."""
    if value in (None, "", 0):
        return None
    try:
        return datetime.fromtimestamp(int(value), tz=UTC)
    except (ValueError, OSError, OverflowError, TypeError):
        return None


async def test_fortigate_credentials(
    host: str, port: int, credentials: dict[str, Any]
) -> tuple[bool, str]:
    """Dry-run probe for the create/edit modal's Test-connection button.

    Reaches ``host:port`` over HTTPS with the API token + VDOM and lists
    interfaces. Returns ``(ok, message)`` — never raises for an expected
    failure.
    """
    from types import SimpleNamespace  # noqa: PLC0415

    driver = FortiGateDHCPDriver()
    fake = SimpleNamespace(id="<test>", name="<test>", host=host, port=port)
    try:
        result = await driver._probe(fake, credentials)
        return result.ok, result.message
    except CloudDHCPError as exc:
        return False, str(exc)
    except Exception as exc:  # noqa: BLE001 — surface any transport error verbatim
        return False, f"fortigate API error: {exc}"


__all__ = ["FortiGateDHCPDriver", "test_fortigate_credentials"]
