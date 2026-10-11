"""Technitium DNS Server — agentless driver for an existing install (#810).

SpatiumDDI ships two Technitium drivers, and the difference is *who owns
the daemon*:

``technitium`` (:mod:`app.drivers.dns.technitium`)
    We deploy the container, an agent sits next to it, the agent mints its
    own API token on first boot and talks to ``127.0.0.1:5380``. The
    control plane never speaks to Technitium — it formulates ops and the
    agent applies them.

``technitium_api`` (this module)
    The operator already runs Technitium somewhere. They paste its API URL
    and a token; the control plane drives the REST API directly, with no
    agent and nothing to deploy. Same shape as ``windows_dns`` Path B and
    the cloud drivers — see :mod:`app.drivers.dns._cloud_base` for the
    agentless contract this builds on.

Both can coexist; a ``DNSServerGroup`` is single-driver, so a mixed estate
means one group each.

**Not a cloud driver**, despite subclassing ``CloudDNSDriverBase``. That
base is misnamed for this use — it is really "agentless driver that keeps a
credential dict" — and everything in it applies. What does *not* apply is
membership of ``CLOUD_DNS_DRIVERS``, which gates the cloud import flow and
the "hosted provider" UI. This driver is operator-hosted on an
operator-supplied URL, which is also why its create/update path runs the
SSRF guard that hosted providers with pinned endpoints do not need.

Credential dict (Fernet-encrypted into ``DNSServer.credentials_encrypted``)::

    {"api_url": "https://dns.example.com:53443",
     "api_token": "<permanent API token>",
     "verify_tls": true}

``api_url`` is the web-service root, NOT the ``/api`` path — 5380 for plain
HTTP, 53443 when ``webServiceEnableTls`` is on. ``verify_tls`` defaults to
**true**; most self-hosted installs use a self-signed cert, so the opt-out
exists, but it has to be a deliberate one.

Auth is a bearer token, required for everything since Technitium 15.0. The
operator mints it in the console (Administration → Sessions → Create Token)
or via ``POST /api/user/createToken``; we never see a password and never
call ``/api/user/login``, so there is no session to expire. Technitium's own
docs recommend a dedicated limited user for token use — SpatiumDDI needs
Zones: Modify and DnsClient: View, not Administrator.

**Errors arrive as HTTP 200.** Technitium answers ``{"status":
"error"|"invalid-token"|"2fa-required", ...}`` with a 200 status line, so
``raise_for_status()`` alone reads every auth failure as an empty success.
Per non-negotiable #5 and the #430 degraded-read guards, that would let a
sync diff live state against nothing and propose deleting the world.
:meth:`_unwrap` is the only way responses are read here — keep it that way.

Scope: zone + record CRUD and topology reads. Online DNSSEC, forwarders and
the native blocklists are the agent driver's today and are deliberately not
advertised in :meth:`capabilities` — ``technitium_api`` is absent from the
router's ``_DRIVER_GATED_OPERATIONS["dnssec_sign"]`` set, so the sign/unsign
endpoints refuse it rather than half-working.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit, urlunsplit

import httpx
import structlog

from app.drivers.dns._cloud_base import (
    CloudDNSDriverBase,
    CloudDNSError,
    CloudDNSProbe,
    CloudDNSZone,
    normalize_fqdn,
)
from app.drivers.dns.base import RecordChange, RecordData
from app.services.technitium.rdata import (
    DNSSEC_RECORD_TYPES,
    SUPPORTED_RECORD_TYPES,
    int_or,
    qualified_name,
    rdata_to_value,
    record_params,
    rel_name,
)

# Technitium's default web-service ports. Used only to build the hint in the
# "no scheme" error below — the operator always supplies the real URL.
_DEFAULT_HTTP_PORT = 5380
_DEFAULT_TLS_PORT = 53443

# Zone types that carry authoritative records we can manage. A Secondary is
# someone else's zone and a Forwarder holds no records, so both are listed
# read-only rather than offered for record CRUD.
_MANAGEABLE_ZONE_TYPES = frozenset({"Primary"})

# Technitium paginates ``/api/zones/list``. 100 keeps responses small while
# rarely needing a second round trip; the loop below handles any total.
_ZONES_PER_PAGE = 100

# Belt-and-braces bound on the zone walk, matching the importer's. A
# runaway pagination loop against a misbehaving endpoint should stop, not
# spin forever holding a request open.
_MAX_ZONES = 5000

_TIMEOUT = httpx.Timeout(connect=10.0, read=60.0, write=10.0, pool=10.0)

logger = structlog.get_logger(__name__)


class TechnitiumAPIDriver(CloudDNSDriverBase):
    """Agentless driver for an operator's own Technitium DNS Server."""

    name = "technitium_api"
    # Rendered by the Add-DNS-server modal and required by the probe.
    # ``verify_tls`` is a checkbox with a default, not a required field.
    credential_fields: tuple[str, ...] = ("api_url", "api_token")

    # ── Credentials + HTTP plumbing ─────────────────────────────────────

    @staticmethod
    def normalize_api_url(raw: str) -> str:
        """Return the web-service root as ``scheme://host[:port]``.

        Operators paste all of ``dns.example.com``, ``https://dns:53443/``
        and ``https://dns:53443/api/`` — accept each and strip back to the
        root, because every path in this driver is built as
        ``<root>/api/<call>``. A bare host with no scheme is rejected
        rather than guessed: assuming ``http`` would silently send a bearer
        token in cleartext.
        """
        url = (raw or "").strip()
        if not url:
            raise CloudDNSError("Technitium credentials missing 'api_url'.")
        parts = urlsplit(url)
        if parts.scheme not in ("http", "https"):
            raise CloudDNSError(
                f"Technitium api_url {url!r} must start with http:// or https:// — "
                f"a scheme cannot be guessed without risking sending the API "
                f"token in cleartext. Technitium serves HTTP on "
                f"{_DEFAULT_HTTP_PORT} and HTTPS on {_DEFAULT_TLS_PORT} when "
                f"webServiceEnableTls is on."
            )
        if not parts.netloc:
            raise CloudDNSError(f"Technitium api_url {url!r} has no host.")
        return urlunsplit((parts.scheme, parts.netloc, "", "", ""))

    def _creds(self, creds: dict[str, Any]) -> tuple[str, str, bool]:
        """Return ``(api_url_root, token, verify_tls)`` or raise."""
        api_url = self.normalize_api_url(str((creds or {}).get("api_url") or ""))
        token = str((creds or {}).get("api_token") or "").strip()
        if not token:
            raise CloudDNSError("Technitium credentials missing 'api_token'.")
        # Absent → verify. Only an explicit false turns verification off, so
        # a credential blob written before this field existed stays strict.
        verify = (creds or {}).get("verify_tls", True)
        return api_url, token, bool(verify)

    def _client(self, api_url: str, token: str, verify: bool) -> httpx.AsyncClient:
        """Return a client bound to the web-service root + bearer token.

        The single seam tests patch to inject a fake transport — keep every
        request flowing through the returned client.
        """
        return httpx.AsyncClient(
            base_url=api_url,
            headers={"Authorization": f"Bearer {token}"},
            timeout=_TIMEOUT,
            verify=verify,
            follow_redirects=False,
        )

    @staticmethod
    def _is_idempotent_noop(message: str) -> bool:
        """True for an error that means "the server is already in that state".

        Non-negotiable #9: tasks must be safe to retry. Technitium rejects a
        replayed create of an identical record ("already exists") and a delete
        of a record that is already gone ("no such record") with a normal
        error envelope — but both mean the op has *already* achieved what it
        asks for. Treating them as failures marks a replayed ``DNSRecordOp``
        row ``failed`` and, worse, aborts a multi-member RRset write partway:
        one member the server already has does not make the remaining members
        optional.

        Same two substrings the agent driver matches, deliberately — the two
        implementations must agree about what counts as converged.
        """
        msg = (message or "").lower()
        return "already exists" in msg or "no such record" in msg

    @classmethod
    def _unwrap(cls, response: Any, what: str) -> Any:
        """Validate a Technitium response envelope and return ``response``.

        Technitium answers HTTP 200 with ``{"status": "error"}`` for
        application-level failures, so the body — not the status line — is
        the authority. ``invalid-token`` is called out separately because it
        is the single most common operator error (a token revoked in the
        console, or one pasted from the wrong user) and "error" alone sends
        people looking in the wrong place.
        """
        status_code = getattr(response, "status_code", 0)
        try:
            body = response.json()
        except (ValueError, TypeError):
            body = {}
        if not isinstance(body, dict):
            body = {}

        status = body.get("status")
        if status == "ok":
            return body.get("response", {})
        if status == "error" and cls._is_idempotent_noop(str(body.get("errorMessage") or "")):
            logger.info(
                "technitium_api.record_op_idempotent_noop",
                request=what,
                detail=body.get("errorMessage"),
            )
            return {}
        if status == "invalid-token":
            raise CloudDNSError(
                f"Technitium rejected the API token on the {what} request. "
                f"Re-create it under Administration → Sessions → Create Token "
                f"and update the server's credentials."
            )
        if status == "2fa-required":
            raise CloudDNSError(
                f"Technitium wants a two-factor code for the {what} request. "
                f"Use a permanent API token rather than a session token — "
                f"tokens are not subject to the 2FA prompt."
            )
        if status is not None:
            detail = body.get("errorMessage") or "no detail"
            raise CloudDNSError(
                f"Technitium rejected the {what} request (status={status!r}): {detail}"
            )
        # No envelope at all: a proxy error page, a wrong URL, or the
        # non-API port. Report the HTTP status, which is all we have.
        raise CloudDNSError(
            f"Technitium returned no API envelope for the {what} request "
            f"(HTTP {status_code}). Check that api_url points at the web "
            f"service root and not a reverse proxy for something else."
        )

    async def _call(
        self,
        client: httpx.AsyncClient,
        path: str,
        what: str,
        params: dict[str, Any] | None = None,
    ) -> Any:
        """GET ``/api/<path>`` and return the unwrapped ``response`` body.

        Technitium accepts GET or form-encoded POST for every call and its
        own console uses GET, so we do too — including for writes.
        """
        try:
            resp = await client.get(f"/api/{path}", params=params or {})
        except httpx.HTTPError as exc:
            # A refused connection raises a ConnectError whose str() is empty,
            # which left "request failed:" with no cause at all (#1613 QA).
            # The class name always says something; the text, when present,
            # says more.
            cause = type(exc).__name__
            if str(exc):
                cause = f"{cause}: {exc}"
            raise CloudDNSError(f"Technitium {what} request failed: {cause}") from exc
        return self._unwrap(resp, what)

    # ── Zone reads ──────────────────────────────────────────────────────

    async def _walk_zones(self, creds: dict[str, Any]) -> list[dict[str, Any]]:
        """Page through ``/api/zones/list`` and return the raw zone dicts.

        The single zone-listing implementation. :meth:`_list_zones` and
        :meth:`pull_zones_from_server` both project from this rather than
        each running their own pagination loop — two loops against the same
        endpoint is how one of them ends up silently missing page 2.

        Technitium's own internal zones (``localhost``, the RFC 1918 reverse
        stubs) carry ``internal: true`` and are dropped here: mirroring them
        would mint rows for zones nobody manages.
        """
        api_url, token, verify = self._creds(creds)
        out: list[dict[str, Any]] = []
        async with self._client(api_url, token, verify) as client:
            page = 1
            while True:
                body = self._as_dict(
                    await self._call(
                        client,
                        "zones/list",
                        "zone list",
                        {"pageNumber": page, "zonesPerPage": _ZONES_PER_PAGE},
                    )
                )
                for z in body.get("zones") or []:
                    if not isinstance(z, dict) or z.get("internal"):
                        continue
                    out.append(z)
                    if len(out) >= _MAX_ZONES:
                        return out
                total_pages = int_or(body.get("totalPages"), 1)
                if page >= total_pages:
                    break
                page += 1
        return out

    @staticmethod
    def _zone_name(raw: dict[str, Any]) -> str:
        """Normalised trailing-dot FQDN for one raw zone dict.

        Technitium reports the root zone as the empty string; ``"."`` is the
        FQDN for it, and normalize_fqdn("") would give ``"."`` anyway — this
        just makes the intent explicit rather than incidental.
        """
        raw_name = str(raw.get("name") or "")
        return normalize_fqdn(raw_name.lower()) if raw_name else "."

    @staticmethod
    def _zone_signed(raw: dict[str, Any]) -> bool:
        """Technitium reports ``dnssecStatus`` as Unsigned / SignedWithNSEC[3]."""
        return str(raw.get("dnssecStatus") or "Unsigned") != "Unsigned"

    async def _list_zones(self, server: Any, creds: dict[str, Any]) -> list[CloudDNSZone]:
        return [
            CloudDNSZone(
                name=self._zone_name(z),
                # Technitium addresses zones by name, so the name IS the
                # handle — there is no opaque id to resolve.
                zone_id=str(z.get("name") or ""),
                is_reverse=self._zone_name(z).endswith((".in-addr.arpa.", ".ip6.arpa.")),
                dnssec_enabled=self._zone_signed(z),
                record_count=None,
            )
            for z in await self._walk_zones(creds)
        ]

    @staticmethod
    def _as_dict(value: Any) -> dict[str, Any]:
        """Coerce an unwrapped ``response`` to a dict.

        A degraded endpoint that answers ``{"status":"ok"}`` with no
        ``response`` key, or with a list/string where a dict belongs, must
        read as "nothing usable" rather than raise an AttributeError three
        frames deeper.
        """
        return value if isinstance(value, dict) else {}

    async def _list_zone_records(
        self, server: Any, creds: dict[str, Any], zone_name: str
    ) -> list[RecordData]:
        api_url, token, verify = self._creds(creds)
        zone_fqdn = normalize_fqdn(zone_name)
        bare = zone_fqdn.rstrip(".")
        records: list[RecordData] = []
        async with self._client(api_url, token, verify) as client:
            body = self._as_dict(
                await self._call(
                    client,
                    "zones/records/get",
                    f"record list for {bare!r}",
                    {"domain": bare, "zone": bare, "listZone": "true"},
                )
            )
            for rec in body.get("records") or []:
                if not isinstance(rec, dict):
                    continue
                rtype = str(rec.get("type") or "").upper()
                # SOA is modelled on the zone row, not as a record; DNSSEC
                # artefacts belong to the signer. Unsupported types drop
                # rather than round-trip through a lossy value string.
                if rtype in DNSSEC_RECORD_TYPES or rtype not in SUPPORTED_RECORD_TYPES:
                    continue
                # Technitium marks a disabled record rather than omitting
                # it. Mirroring one would claim SpatiumDDI serves a record
                # the daemon is deliberately not answering with.
                if rec.get("disabled"):
                    continue
                rdata = rec.get("rData")
                if not isinstance(rdata, dict):
                    continue
                value, extra = rdata_to_value(rtype, rdata)
                if not value:
                    continue
                records.append(
                    RecordData(
                        name=rel_name(str(rec.get("name") or ""), zone_fqdn),
                        record_type=rtype,
                        value=value,
                        ttl=int_or(rec.get("ttl"), 3600),
                        priority=extra.get("priority"),
                        weight=extra.get("weight"),
                        port=extra.get("port"),
                    )
                )
        return records

    # ── Record writes ───────────────────────────────────────────────────

    async def _apply_record(self, server: Any, creds: dict[str, Any], change: RecordChange) -> None:
        """Apply one record op, expressed as a whole-RRset write where possible.

        The API is one record per call and a ``RecordChange`` names only the
        NEW value, so a value *change* cannot be said directly: there is no
        "replace THIS RR". ``overwrite=true`` on ``add`` is the nearest
        primitive — it clears the rrset at ``(domain, type)`` and writes the
        given value.

        **``overwrite=false`` on a create/update is a bug, not a style
        choice.** Technitium *appends* at that setting, so editing
        ``www A 10.0.0.1`` to ``10.0.0.2`` leaves the zone answering both,
        round-robin, forever — verified live against 15.4.0 and documented at
        length in the agent driver, which carries the same warning. Unlike the
        agent path there is no structural reload to eventually re-converge it.

        ``change.rrset`` (#783) carries the complete desired set, which is the
        only place that knowledge exists. With it, create/update replays the
        whole set: member 0 with ``overwrite=true`` to clear, the rest
        appended. That keeps a name with several values — round-robin A, a
        backup MX, SPF beside a verification TXT — from collapsing to
        whichever op landed last. Member 0 always lands first, so a
        mid-sequence failure leaves a subset containing it rather than an
        empty name, and the op is replayed.

        ``rrset is None`` means the caller opted out (DNS pools, the cutover
        pre-flight) or the op predates the field; per the ``RRsetData``
        contract, fall back to single-value REPLACE semantics.

        A ``delete`` stays value-scoped either way: the op's own params
        identify exactly the RR to remove, the survivors are already correct
        on the server, and Technitium drops the rrset once its last record
        goes. One call, nothing at risk.
        """
        api_url, token, verify = self._creds(creds)
        rec = change.record
        rtype = rec.record_type.upper()
        if rtype not in SUPPORTED_RECORD_TYPES:
            raise CloudDNSError(
                f"Technitium driver does not manage {rtype} records "
                f"(supported: {', '.join(sorted(SUPPORTED_RECORD_TYPES))})."
            )
        if change.op not in ("create", "update", "delete"):
            raise CloudDNSError(f"Technitium: unsupported record op {change.op!r}")

        zone_bare = normalize_fqdn(change.zone_name).rstrip(".")
        domain = qualified_name(zone_bare, rec.name)
        base = {"domain": domain, "zone": zone_bare, "type": rtype}

        def _params(r: RecordData) -> dict[str, Any]:
            return record_params(rtype, r.value, priority=r.priority, weight=r.weight, port=r.port)

        async with self._client(api_url, token, verify) as client:
            if change.op == "delete":
                # The value params are load-bearing on delete: they are how
                # Technitium picks WHICH member of an rrset to remove.
                # Dropping them would delete a sibling round-robin A record.
                await self._call(
                    client,
                    "zones/records/delete",
                    f"delete {rtype} {domain}",
                    {**base, **_params(rec)},
                )
                return

            # Absence, not falsiness — TTL 0 is legal ("never cache this").
            members = list(change.rrset.as_records(rec)) if change.rrset is not None else [rec]
            if not members:
                # An empty desired set means the RRset should not exist. The
                # op that produced it is a delete in everything but name, so
                # remove the value it names rather than writing nothing and
                # reporting success.
                await self._call(
                    client,
                    "zones/records/delete",
                    f"delete {rtype} {domain}",
                    {**base, **_params(rec)},
                )
                return

            for index, member in enumerate(members):
                ttl = 3600 if member.ttl is None else member.ttl
                await self._call(
                    client,
                    "zones/records/add",
                    f"{change.op} {rtype} {domain}",
                    {
                        **base,
                        **_params(member),
                        "ttl": ttl,
                        # Member 0 clears the rrset; the rest append to it.
                        "overwrite": "true" if index == 0 else "false",
                    },
                )

    # ── Zone writes ─────────────────────────────────────────────────────

    async def _apply_zone(
        self,
        server: Any,
        creds: dict[str, Any],
        zone: Any,
        op: str,
        *,
        managed_records: list[RecordData] | None = None,
    ) -> bool | None:
        api_url, token, verify = self._creds(creds)
        bare = normalize_fqdn(str(getattr(zone, "name", ""))).rstrip(".")
        if not bare:
            raise CloudDNSError("Technitium: zone name is required.")
        # Only Primary is claimed in ``capabilities()["zone_types"]``, and
        # that has to be enforced here rather than papered over: Technitium's
        # create takes a ``type``, and defaulting a secondary / stub / forward
        # zone to Primary would mint an EMPTY authoritative zone on the
        # operator's live server. That is not a degraded result — the whole
        # domain starts answering NXDOMAIN from a server that used to
        # transfer or forward it.
        zone_type = str(getattr(zone, "zone_type", "primary") or "primary").lower()
        if op == "create" and zone_type != "primary":
            raise CloudDNSError(
                f"The agentless Technitium driver creates primary zones only; "
                f"{bare!r} is {zone_type!r}. Create it in the Technitium console "
                f"(where its primaries / forwarders are configured) and pull it "
                f"in with sync-from-server, or use the agent-managed "
                f"'technitium' driver, which supports secondary / stub / "
                f"forward zones."
            )

        async with self._client(api_url, token, verify) as client:
            if op == "create":
                created = await self._call(
                    client,
                    "zones/create",
                    f"create zone {bare!r}",
                    {"zone": bare, "type": "Primary"},
                )
                # A created zone answers ``{"domain": …}``; ``_unwrap``
                # turns "Zone already exists" into an empty body (#1537),
                # i.e. the zone was already there and nothing changed.
                return bool(created)
            if op == "delete":
                try:
                    await self._call(
                        client, "zones/delete", f"delete zone {bare!r}", {"zone": bare}
                    )
                except CloudDNSError as exc:
                    # #1537 — Technitium answers "No such zone was found: x"
                    # for a zone that is already gone. Matched on the error
                    # envelope text only; invalid-token / 2fa / transport
                    # errors have different messages and still raise.
                    # "...: no such zone exists." is the same answer when
                    # the zone vanishes between Technitium's own lookup and
                    # its delete.
                    msg = str(exc).lower()
                    if "no such zone was found" in msg or "no such zone exists" in msg:
                        logger.info(
                            "technitium_api.zone_delete_noop_absent",
                            server=str(getattr(server, "id", "")),
                            zone=bare,
                        )
                        return False
                    raise
                return True
            # Unreachable while ``CloudDNSDriverBase.apply_zone_change``
            # validates op first — kept so this method is safe to call
            # directly, and asserted by
            # test_unsupported_zone_op_is_refused_before_any_request.
            raise CloudDNSError(f"Technitium: unsupported zone op {op!r}")

    # ── Probe ───────────────────────────────────────────────────────────

    async def probe(self, server: Any) -> CloudDNSProbe:
        """Auth + liveness check behind ``POST …/servers/{id}/test-connection``.

        Uses ``/api/dnsClient/healthCheck``, which Technitium documents as
        the automated-health-check call: it confirms the process is up *and*
        that it resolves, and its docs state it generates no query-log
        entries — so a 60-second UI poll cannot bury an operator's real
        query log. The zone count comes from a second call so the message
        says something useful about what the token can see.
        """
        try:
            creds = self._load_credentials(server)
            api_url, token, verify = self._creds(creds)
        except CloudDNSError as exc:
            return CloudDNSProbe(ok=False, message=str(exc))

        try:
            async with self._client(api_url, token, verify) as client:
                await self._call(client, "dnsClient/healthCheck", "health check")
        except CloudDNSError as exc:
            return CloudDNSProbe(ok=False, message=str(exc))
        except Exception as exc:  # noqa: BLE001 — surface any transport error cleanly
            return CloudDNSProbe(ok=False, message=f"Technitium API error: {exc}")

        # Auth is already proven; a failure counting zones is worth
        # reporting but must not turn a working connection into a red X —
        # a token scoped to Zones:View on a subset legitimately sees fewer.
        try:
            zones = await self.pull_zones_from_server(server)
        except (CloudDNSError, httpx.HTTPError) as exc:
            return CloudDNSProbe(
                ok=True,
                message=f"Authenticated, but listing zones failed: {exc}",
            )
        return CloudDNSProbe(
            ok=True,
            message=f"Authenticated; {len(zones)} zone(s) visible to this token.",
            zone_count=len(zones),
        )

    # ── Topology pull shape ─────────────────────────────────────────────

    async def pull_zones_from_server(self, server: Any) -> list[dict[str, Any]]:
        """List zones, preserving Technitium's own zone type.

        The base class hardcodes ``"Primary"`` because a cloud provider
        hosts nothing else. Technitium serves Secondary / Stub / Forwarder
        zones too, and calling one of those Primary would let the
        sync-from-server path adopt someone else's zone as authoritative.
        """
        creds = self._load_credentials(server)
        out: list[dict[str, Any]] = []
        for z in await self._walk_zones(creds):
            name = self._zone_name(z)
            ztype = str(z.get("type") or "Primary")
            out.append(
                {
                    "name": name,
                    "zone_type": ztype,
                    "is_reverse_lookup": name.endswith((".in-addr.arpa.", ".ip6.arpa.")),
                    "dnssec_enabled": self._zone_signed(z),
                    "zone_id": str(z.get("name") or ""),
                    "record_count": None,
                    # Surfaced so the sync-from-server UI can explain why a
                    # Secondary is listed but not adoptable.
                    "manageable": ztype in _MANAGEABLE_ZONE_TYPES,
                }
            )
        return out

    # ── Capabilities ────────────────────────────────────────────────────

    def capabilities(self) -> dict[str, Any]:
        return {
            "name": "technitium_api",
            "agentless": True,
            "manages_zones": True,
            "topology_pull": True,
            "views": False,
            "rpz": False,
            # Technitium signs online and the agent-managed driver drives it,
            # but this driver does not yet — and half-advertising it would
            # put a Sign button on a zone nothing would ever sign. The REST
            # gate agrees: ``technitium_api`` is absent from
            # ``_DRIVER_GATED_OPERATIONS["dnssec_sign"]``.
            "dnssec_online": False,
            "dnssec_inline_signing": False,
            "incremental_updates": "rest_api",
            "zone_types": sorted(_MANAGEABLE_ZONE_TYPES),
            "record_types": sorted(SUPPORTED_RECORD_TYPES),
            "alias_records": False,
            "lua_records": False,
            "catalog_zones": False,
            "notes": (
                "Agentless driver for a Technitium DNS Server the operator "
                "already runs. Zones + records are managed from the control "
                "plane over Technitium's HTTP API with a bearer token; there "
                "is no agent to deploy. DNSSEC, forwarders and the native "
                "blocklists remain on the agent-managed 'technitium' driver."
            ),
        }


__all__ = ["TechnitiumAPIDriver"]
