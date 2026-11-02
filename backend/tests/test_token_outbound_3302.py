"""A ``read``-scoped API token never makes SpatiumDDI send traffic outward (#3302).

Two surfaces let a ``read`` token cause outbound traffic that the REST
``/tools/*`` probes (which are POSTs, so ``read`` never reached them) refuse:

* the MCP endpoint, which ``read`` may POST to, dispatched every non-write,
  non-``propose_*`` tool — ``network_ping``, ``find_dns_zone_drift`` (a live
  AXFR / pull from every server) and the off-prem lookups among them;
* GET routes that probe, pull live state from a managed server or look
  something up off-prem, which ``read`` covered because they are GETs.

Now a tool sets ``outbound=True`` and MCP hides it from a token with no write
scope, and a GET carries ``@token_outbound`` and the scope gate stops ``read``
covering it. A session, an unrestricted token, or a write scope whose prefix
covers the path keeps today's behaviour.
"""

from __future__ import annotations

import ast
import inspect
import re
import textwrap
import uuid
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import generate_api_token, hash_password
from app.models.auth import APIToken, User
from app.services import feature_modules
from app.services.ai.tools import REGISTRY
from app.services.api_token_scopes import (
    is_token_outbound,
    scope_matches_request,
    scopes_allow_outbound,
)
from app.services.nettools.schemas import CommandResult

# Every route carrying ``@token_outbound``, verified to contact another host.
# Pinned so that adding (or dropping) the marker is a reviewed decision.
EXPECTED_OUTBOUND_ROUTES: frozenset[tuple[str, str]] = frozenset(
    {
        # AXFR / WinRM / cloud-API pull of the live zone from every server.
        ("GET", "/api/v1/dns/groups/{group_id}/zones/{zone_id}/drift"),
        # FortiOS REST call to the FortiGate.
        ("GET", "/api/v1/dhcp/servers/{server_id}/fortigate-interfaces"),
        # Reads the backup destination (S3 / SFTP / SMB / WebDAV / …).
        ("GET", "/api/v1/backup/targets/{target_id}/archives"),
        ("GET", "/api/v1/backup/targets/{target_id}/archives/latest/download"),
        ("GET", "/api/v1/backup/targets/{target_id}/archives/{filename}/download"),
        ("GET", "/api/v1/backup/targets/{target_id}/archives/{filename}/manifest-preview"),
        # RIPEstat / PeeringDB (off-prem).
        ("GET", "/api/v1/bgp/asn/{asn}/announced-prefixes"),
        ("GET", "/api/v1/bgp/asn/{asn}/overview"),
        ("GET", "/api/v1/bgp/asn/{asn}/network"),
        ("GET", "/api/v1/bgp/asn/{asn}/ixps"),
        ("GET", "/api/v1/bgp/prefix/origin"),
        ("GET", "/api/v1/bgp/prefix/routing-history"),
        # crt.sh (off-prem).
        ("GET", "/api/v1/tls-certs/{target_id}/ct-log"),
        # GitHub releases (off-prem).
        ("GET", "/api/v1/appliance/releases"),
        ("GET", "/api/v1/appliance/upgrade-images/available"),
        # The operator's LLM provider.
        ("GET", "/api/v1/ai/providers/{provider_id}/models"),
        # The appliance's own kubeapi, through the supervisor proxy.
        ("GET", "/api/v1/appliance/appliances/{appliance_id}/k8s/workloads"),
        ("GET", "/api/v1/appliance/appliances/{appliance_id}/k8s/pods"),
        ("GET", "/api/v1/appliance/appliances/{appliance_id}/k8s/logs"),
    }
)

# Every tool registered ``outbound=True``. Pinned for the same reason.
EXPECTED_OUTBOUND_TOOLS: frozenset[str] = frozenset(
    {
        # Probes from the SpatiumDDI host.
        "network_ping",
        "network_traceroute",
        "network_dig",
        "network_port_test",
        "network_tls_cert",
        "ping_host",
        "tls_cert_check",
        "forward_dns",
        "reverse_dns",
        # Live pulls from managed servers / destinations.
        "find_dns_zone_drift",
        "list_backup_archives_at_target",
        "find_cutover_parity_check",
        "find_dns_import_preview",
        "find_dhcp_import_preview",
        "find_netbox_import_preview",
        # Off-prem lookups.
        "network_whois",
        "lookup_whois_ip",
        "lookup_whois_asn",
        "lookup_whois_domain",
        "asn_announced_prefixes",
        "asn_ixp_presence",
        "asn_peering_profile",
        "prefix_origin",
        "prefix_routing_history",
        "find_ct_log_entries",
        "find_available_upgrade_images",
    }
)

# Fully-qualified helpers (or helper prefixes) that send traffic off the
# SpatiumDDI host. A tool executor that reaches one — directly, or through a
# helper in its own module — must be ``outbound=True``.
_OUTBOUND_HELPERS: tuple[str, ...] = (
    "socket",
    "ssl",
    "httpx",
    "subprocess",
    "asyncio.create_subprocess_exec",
    "asyncio.create_subprocess_shell",
    "dns.resolver",
    "dns.query",
    "winrm",
    "app.services.nettools.run_",
    "app.services.nettools.test_port",
    "app.services.nettools.inspect_tls_cert",
    "app.services.bgp.fetch_",
    "app.services.rdap.",
    "app.services.rdap_",
    "app.services.tls_cert.ct_log",
    "app.services.dns.drift",
    "app.services.backup.targets.get_destination",
    "app.services.cutover.parity",
    "app.services.ai.operations_writes._dns_import_pull",
    "app.services.ai.operations_writes._dhcp_import_pull",
    "app.services.ai.operations_writes._netbox_import_pull",
    "app.services.appliance.releases.list_available_upgrade_images",
    "app.drivers.",
)

# A tool that spends a network-tool budget but only reads the database.
_RATE_LIMITED_NOT_OUTBOUND: frozenset[str] = frozenset({"lookup_mac_vendor"})


def _references(fn: Any) -> set[str]:
    """Fully-qualified names the executor reaches, following helpers defined
    in its own module. Resolves both module-level and function-local
    imports, and ``module.attr`` on an imported module."""
    module = inspect.getmodule(fn)
    tree = ast.parse(textwrap.dedent(inspect.getsource(module)))
    imports: dict[str, str] = {}

    def note_import(node: ast.AST) -> None:
        if isinstance(node, ast.ImportFrom) and node.module:
            for a in node.names:
                imports.setdefault(a.asname or a.name, f"{node.module}.{a.name}")
        elif isinstance(node, ast.Import):
            for a in node.names:
                # ``import a.b`` binds ``a``; the chain resolves from there.
                if a.asname:
                    imports.setdefault(a.asname, a.name)
                else:
                    head = a.name.split(".")[0]
                    imports.setdefault(head, head)

    for node in tree.body:
        note_import(node)
    funcs = {n.name: n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}
    refs: set[str] = set()
    seen: set[str] = set()
    stack = [funcs[fn.__name__]]
    while stack:
        g = stack.pop()
        if g.name in seen:
            continue
        seen.add(g.name)
        for n in ast.walk(g):
            note_import(n)
        for n in ast.walk(g):
            if isinstance(n, ast.Name):
                if n.id in funcs and n.id not in seen:
                    stack.append(funcs[n.id])
                if n.id in imports:
                    refs.add(imports[n.id])
            elif isinstance(n, ast.Attribute):
                chain = [n.attr]
                v = n.value
                while isinstance(v, ast.Attribute):
                    chain.append(v.attr)
                    v = v.value
                if isinstance(v, ast.Name) and v.id in imports:
                    refs.add(".".join([imports[v.id], *reversed(chain)]))
    return refs


def _is_outbound_helper(ref: str) -> bool:
    for h in _OUTBOUND_HELPERS:
        if h.endswith(("_", ".")):
            if ref.startswith(h):
                return True
        elif ref == h or ref.startswith(h + "."):
            return True
    return False


def _reaches_outbound_helper(fn: Any) -> list[str]:
    return sorted(r for r in _references(fn) if _is_outbound_helper(r))


def test_outbound_tools_are_exactly_the_reviewed_set() -> None:
    flagged = {t.name for t in REGISTRY.all() if t.outbound}
    assert flagged == set(EXPECTED_OUTBOUND_TOOLS)


def test_the_helper_scan_sees_every_outbound_tool() -> None:
    """The scan below is only worth something if it recognises the tools we
    already know are outbound — otherwise it passes by seeing nothing."""
    blind = sorted(
        t.name for t in REGISTRY.all() if t.outbound and not _reaches_outbound_helper(t.executor)
    )
    assert not blind, f"outbound tools the helper scan does not recognise: {blind}"


def test_no_tool_reaching_a_network_helper_is_left_unflagged() -> None:
    """A read tool that reaches a known network / subprocess helper must be
    ``outbound=True``, or a ``read`` token could drive it over MCP."""
    missing = {}
    for tool in REGISTRY.read_only():
        if tool.outbound or tool.name.startswith("propose_"):
            continue
        hits = _reaches_outbound_helper(tool.executor)
        if hits:
            missing[tool.name] = hits
    assert not missing, f"tools reach outbound helpers but are not outbound=True: {missing}"


def test_rate_limited_tools_are_outbound() -> None:
    """``rate_limit`` is the network-tool budget, so a tool spending it is
    almost always outbound — the exceptions are listed by name."""
    stray = {
        t.name
        for t in REGISTRY.all()
        if t.rate_limit is not None and not t.outbound and t.name not in _RATE_LIMITED_NOT_OUTBOUND
    }
    assert not stray, stray


def _routes() -> dict[tuple[str, str], object]:
    from app.main import app  # noqa: PLC0415

    found: dict[tuple[str, str], object] = {}

    def rec(routes, prefix: str = "") -> None:  # type: ignore[no-untyped-def]
        for r in routes:
            if hasattr(r, "original_router"):
                rec(r.original_router.routes, prefix + r.include_context.prefix)
            elif hasattr(r, "endpoint"):
                for m in getattr(r, "methods", ()) or ():
                    found[(m, re.sub(r":\w+}", "}", prefix + r.path))] = r.endpoint

    rec(app.routes)
    return found


def test_outbound_routes_are_exactly_the_reviewed_set() -> None:
    marked = {k for k, ep in _routes().items() if is_token_outbound(ep) and k[0] != "HEAD"}
    assert marked == set(EXPECTED_OUTBOUND_ROUTES)


def test_scope_matching_on_an_outbound_route() -> None:
    drift = "/api/v1/dns/groups/g/zones/z/drift"
    assert scope_matches_request(["read"], "GET", drift) is True
    assert scope_matches_request(["read"], "GET", drift, outbound_route=True) is False
    # A write scope covering the path, or no scopes at all, still pass.
    assert scope_matches_request(["read", "dns:write"], "GET", drift, outbound_route=True)
    assert scope_matches_request([], "GET", drift, outbound_route=True)
    # A write scope that does not cover the path does not.
    assert not scope_matches_request(["ipam:write"], "GET", drift, outbound_route=True)

    assert scopes_allow_outbound([]) is True
    assert scopes_allow_outbound(["read", "ipam:write"]) is True
    assert scopes_allow_outbound(["read"]) is False
    assert scopes_allow_outbound(["read", "agent"]) is False


# ── HTTP ─────────────────────────────────────────────────────────────────


@pytest.fixture(autouse=True)
def _reset_module_cache():
    feature_modules.invalidate_cache()
    yield
    feature_modules.invalidate_cache()


class _CountingRedis:
    """In-memory stand-in for the network-tool budget counter."""

    def __init__(self) -> None:
        self.counts: dict[str, int] = {}

    def __call__(self, *_a: Any, **_kw: Any) -> _CountingRedis:
        return self

    async def eval(self, _script: str, _numkeys: int, key: str, *_args: Any) -> int:
        self.counts[key] = self.counts.get(key, 0) + 1
        return self.counts[key]

    async def aclose(self) -> None:
        return None


@pytest.fixture
def no_real_ping(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Record pings instead of sending them."""
    sent: list[str] = []

    async def fake_ping(host: str, **_kw: Any) -> CommandResult:
        sent.append(host)
        return CommandResult(
            tool="ping", argv=["ping", host], available=True, exit_code=0, stdout="ok"
        )

    monkeypatch.setattr("app.services.ai.tools.nettools.run_ping", fake_ping)
    monkeypatch.setattr("app.services.nettools.throttle.make_async_redis", _CountingRedis())
    return sent


async def _token(db: AsyncSession, scopes: list[str]) -> str:
    owner = User(
        username=f"tok-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="Token Owner",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    db.add(owner)
    await db.flush()
    raw, _prefix, token_hash = generate_api_token()
    db.add(
        APIToken(
            name=f"t-{uuid.uuid4().hex[:6]}",
            token_hash=token_hash,
            prefix=raw[:10],
            scope="user",
            scopes=scopes,
            user_id=owner.id,
            created_by_user_id=owner.id,
            is_active=True,
        )
    )
    await db.flush()
    await db.commit()
    return raw


def _h(raw: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {raw}"}


async def _mcp(client: AsyncClient, raw: str, method: str, params: dict | None = None) -> dict:
    r = await client.post(
        "/api/v1/ai/mcp",
        json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}},
        headers=_h(raw),
    )
    assert r.status_code == 200, r.text
    return r.json()


async def _listed(client: AsyncClient, raw: str) -> set[str]:
    return {t["name"] for t in (await _mcp(client, raw, "tools/list"))["result"]["tools"]}


@pytest.mark.asyncio
async def test_read_token_does_not_see_or_call_outbound_mcp_tools(
    client: AsyncClient, db_session: AsyncSession, no_real_ping: list[str]
) -> None:
    raw = await _token(db_session, ["read"])
    listed = await _listed(client, raw)
    assert "network_ping" not in listed
    assert listed.isdisjoint(EXPECTED_OUTBOUND_TOOLS)
    # A non-outbound read tool is still there, so the list is not just empty.
    assert "list_ip_spaces" in listed

    resp = await _mcp(
        client, raw, "tools/call", {"name": "network_ping", "arguments": {"host": "192.0.2.1"}}
    )
    assert "error" in resp, resp
    assert no_real_ping == []

    info = (await client.get("/api/v1/ai/mcp", headers=_h(raw))).json()
    assert info["available_tools"] == len(listed)


@pytest.mark.asyncio
@pytest.mark.parametrize("scopes", [[], ["read", "dns:write"]])
async def test_unrestricted_or_write_token_keeps_outbound_mcp_tools(
    client: AsyncClient,
    db_session: AsyncSession,
    no_real_ping: list[str],
    scopes: list[str],
) -> None:
    raw = await _token(db_session, scopes)
    assert "network_ping" in await _listed(client, raw)
    resp = await _mcp(
        client, raw, "tools/call", {"name": "network_ping", "arguments": {"host": "192.0.2.1"}}
    )
    assert "error" not in resp, resp
    assert resp["result"]["isError"] is False
    assert no_real_ping == ["192.0.2.1"]


@pytest.mark.asyncio
async def test_read_token_is_refused_on_an_outbound_get(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    raw = await _token(db_session, ["read"])
    path = f"/api/v1/dns/groups/{uuid.uuid4()}/zones/{uuid.uuid4()}/drift"
    r = await client.get(path, headers=_h(raw))
    assert r.status_code == 403, r.text
    assert "contact another host" in r.json()["detail"]
    # An ordinary GET on the same router still reads.
    assert (await client.get("/api/v1/dns/groups", headers=_h(raw))).status_code == 200


@pytest.mark.asyncio
@pytest.mark.parametrize("scopes", [[], ["read", "dns:write"]])
async def test_unrestricted_or_covering_write_token_reaches_an_outbound_get(
    client: AsyncClient, db_session: AsyncSession, scopes: list[str]
) -> None:
    raw = await _token(db_session, scopes)
    path = f"/api/v1/dns/groups/{uuid.uuid4()}/zones/{uuid.uuid4()}/drift"
    r = await client.get(path, headers=_h(raw))
    # Past the scope gate: the zone does not exist.
    assert r.status_code == 404, r.text
