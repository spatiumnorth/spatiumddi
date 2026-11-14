"""A ``read``-scoped API token never makes SpatiumDDI send traffic outward (#3302).

Two surfaces let a ``read`` token cause outbound traffic that the REST
``/tools/*`` probes (which are POSTs, so ``read`` never reached them) refuse:

* the MCP endpoint, which ``read`` may POST to, dispatched every non-write,
  non-``propose_*`` tool — ``network_ping``, ``find_dns_zone_drift`` (a live
  AXFR / pull from every server) and the off-prem lookups among them;
* GET routes that probe, pull live state from a managed server or look
  something up off-prem, which ``read`` covered because they are GETs.

Now a tool sets ``outbound=True`` and MCP hides it from a scoped token unless
the token holds the tool's ``outbound_scope`` (the write scope its REST route
needs), and a GET carries ``@token_outbound`` and the scope gate stops
``read`` covering it. A session, an unrestricted token, or a write scope
whose prefix covers the path keeps today's behaviour.
"""

from __future__ import annotations

import ast
import functools
import importlib
import importlib.util
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
    scopes_allow_outbound_tool,
)
from app.services.nettools.schemas import CommandResult
from app.services.upgrades.preflight import run_all as preflight_run_all

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
        # The self-test resolves registry-1.docker.io through the host resolver.
        ("GET", "/api/v1/appliance/diagnostics/bundle"),
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
        # The self-test resolves registry-1.docker.io (appliance only).
        "get_support_bundle_preview",
    }
)

# Network / subprocess libraries. Reaching one anywhere below a tool or a GET
# handler — through any chain of ``app.*`` functions — counts as outbound.
_NETWORK_LIBS: tuple[str, ...] = (
    "socket",
    "ssl",
    "httpx",
    "aiohttp",
    "requests",
    "subprocess",
    "asyncio.create_subprocess_exec",
    "asyncio.create_subprocess_shell",
    "asyncio.open_connection",
    "dns.resolver",
    "dns.asyncresolver",
    "dns.query",
    "dns.asyncquery",
    "winrm",
    "paramiko",
    "asyncssh",
    "boto3",
)

# Service-level helpers (or prefixes) that send traffic off the host through
# an object the AST walk cannot follow (a driver instance, a destination). A
# tool executor that names one in its own module must be ``outbound=True``.
_OUTBOUND_HELPERS: tuple[str, ...] = (
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

# Tools / GET routes that reach a network library but only talk to SpatiumDDI's
# own infrastructure, so are not outbound. Each is a reviewed decision.
_LOCAL_INFRA_TOOLS: dict[str, str] = {
    "find_cluster_metrics": "cluster DNS + the cluster's own nodes' kubelets",
    "find_services": "the local docker socket (compose service control)",
    "find_upgrade_preflight": "the in-cluster slot-image mirror",
}
_LOCAL_INFRA_GET_ROUTES: dict[str, str] = {
    "/api/v1/admin/containers/stats": "the local docker socket",
    "/api/v1/admin/containers/pods/{name}/logs/stream": "the local kubeapi (#3761)",
    "/api/v1/appliance/cluster/health": "cluster DNS + the cluster's own nodes' kubelets",
    "/api/v1/appliance/cluster/health/stream": "as /appliance/cluster/health",
    "/api/v1/appliance/containers/workloads/{component}/logs/stream": "the local kubeapi",
    "/api/v1/appliance/containers/{name}/logs/stream": "the local kubeapi",
    "/api/v1/appliance/upgrade-images/{image_id}/raw.xz": "the in-cluster slot-image mirror",
    "/api/v1/system/services": "the local docker socket",
    "/api/v1/upgrades/preflight": "the in-cluster slot-image mirror",
    # Unauthenticated OIDC redirect leg: no API token ever reaches it.
    "/api/v1/auth/{provider_id}/authorize": "OIDC discovery; not token-authenticated",
    "/api/v1/auth/{provider_id}/callback": "OIDC token exchange; not token-authenticated",
}

# Modules the walk does not descend into: they name a network library only to
# classify an error (``socket.gaierror``), never to open a connection.
_NOT_FOLLOWED: tuple[str, ...] = ("app.core.db_transient",)


def _matches(ref: str, prefixes: tuple[str, ...]) -> bool:
    for h in prefixes:
        if h.endswith(("_", ".")):
            if ref.startswith(h):
                return True
        elif ref == h or ref.startswith(h + "."):
            return True
    return False


@functools.cache
def _module_index(modname: str) -> tuple[dict[str, str], dict[str, ast.AST]] | None:
    """(name -> fully-qualified import, function name -> def node) for a module."""
    try:
        module = importlib.import_module(modname)
        tree = ast.parse(textwrap.dedent(inspect.getsource(module)))
    except (ImportError, OSError, TypeError):
        return None
    package = modname if hasattr(module, "__path__") else modname.rpartition(".")[0]
    imports: dict[str, str] = {}
    funcs: dict[str, ast.AST] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module is not None:
            base = node.module
            if node.level:
                base = importlib.util.resolve_name("." * node.level + node.module, package)
            for a in node.names:
                imports.setdefault(a.asname or a.name, f"{base}.{a.name}")
        elif isinstance(node, ast.Import):
            for a in node.names:
                # ``import a.b`` binds ``a``; the chain resolves from there.
                head = a.name if a.asname else a.name.split(".")[0]
                imports.setdefault(a.asname or head, head)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            funcs.setdefault(node.name, node)
    return imports, funcs


def _resolve_function(dotted: str) -> tuple[str, str] | None:
    """``app.x.y.f`` -> (module, name) when it names a function."""
    parts = dotted.split(".")
    for i in range(len(parts) - 1, 0, -1):
        try:
            obj: Any = importlib.import_module(".".join(parts[:i]))
        except ImportError:
            continue
        for attr in parts[i:]:
            obj = getattr(obj, attr, None)
        if inspect.isfunction(obj):
            obj = inspect.unwrap(obj)
            return obj.__module__, obj.__name__
        return None
    return None


def _references(fn: Any) -> list[tuple[str, int]]:
    """Fully-qualified names ``fn`` reaches, with the call depth at which each
    is named: 0 for ``fn``'s own module (its local helpers included), +1 for
    each ``app.*`` function followed into another module."""
    fn = inspect.unwrap(fn)
    found: list[tuple[str, int]] = []
    seen: set[tuple[str, str]] = set()
    stack: list[tuple[str, str, int]] = [(fn.__module__, fn.__name__, 0)]
    while stack:
        modname, fname, depth = stack.pop()
        if (modname, fname) in seen or depth > 6:
            continue
        seen.add((modname, fname))
        index = _module_index(modname)
        if index is None or fname not in index[1]:
            continue
        imports, funcs = index
        for n in ast.walk(funcs[fname]):
            ref = None
            if isinstance(n, ast.Name):
                if n.id in funcs and n.id != fname:
                    stack.append((modname, n.id, depth))
                ref = imports.get(n.id)
            elif isinstance(n, ast.Attribute):
                chain = [n.attr]
                v = n.value
                while isinstance(v, ast.Attribute):
                    chain.append(v.attr)
                    v = v.value
                if isinstance(v, ast.Name) and v.id in imports:
                    ref = ".".join([imports[v.id], *reversed(chain)])
            if ref is None:
                continue
            found.append((ref, depth))
            if (
                ref.startswith("app.")
                and not _matches(ref, _NOT_FOLLOWED)
                and (target := _resolve_function(ref)) is not None
            ):
                stack.append((*target, depth + 1))
    return found


def _reaches_outbound_helper(fn: Any) -> list[str]:
    return sorted(
        {
            ref
            for ref, depth in _references(fn)
            if _matches(ref, _NETWORK_LIBS) or (depth == 0 and _matches(ref, _OUTBOUND_HELPERS))
        }
    )


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
        if tool.outbound or tool.name.startswith("propose_") or tool.name in _LOCAL_INFRA_TOOLS:
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

    # MCP: a scoped token gets an outbound tool only with the write scope its
    # REST equivalent needs; a probe (``/tools/*``, no write scope) never.
    assert scopes_allow_outbound_tool([], None) is True
    assert scopes_allow_outbound_tool(["read"], "dns:write") is False
    assert scopes_allow_outbound_tool(["read", "dns:write"], "dns:write") is True
    assert scopes_allow_outbound_tool(["read", "ipam:write"], "dns:write") is False
    assert (
        scopes_allow_outbound_tool(["read", "ipam:write", "dns:write", "dhcp:write"], None) is False
    )


# Outbound tools whose REST equivalent a write scope covers. Pinned against
# the REST prefix it mirrors, so the two surfaces cannot drift apart.
EXPECTED_OUTBOUND_SCOPES: dict[str, tuple[str, str]] = {
    "find_dns_zone_drift": ("dns:write", "/api/v1/dns/groups/g/zones/z/drift"),
    "find_dns_import_preview": ("dns:write", "/api/v1/dns/import/cloud/preview"),
    "find_dhcp_import_preview": ("dhcp:write", "/api/v1/dhcp/import/windows/preview"),
    "find_netbox_import_preview": ("ipam:write", "/api/v1/ipam/import/netbox/preview"),
}


def test_outbound_scopes_match_the_rest_route_they_mirror() -> None:
    declared = {t.name: t.outbound_scope for t in REGISTRY.all() if t.outbound_scope is not None}
    assert declared == {n: scope for n, (scope, _p) in EXPECTED_OUTBOUND_SCOPES.items()}
    for _name, (scope, path) in EXPECTED_OUTBOUND_SCOPES.items():
        # The same scope, alone, is what REST needs for the equivalent route.
        assert scope_matches_request([scope], "POST", path)
        assert not scope_matches_request(["read"], "POST", path)


def test_get_routes_reaching_the_network_are_marked() -> None:
    """A GET handler that reaches a network / subprocess library through any
    chain of ``app.*`` functions must carry ``@token_outbound``, or be a
    reviewed local-infrastructure exception."""
    stray = {}
    for (method, path), endpoint in _routes().items():
        if method != "GET" or is_token_outbound(endpoint) or path in _LOCAL_INFRA_GET_ROUTES:
            continue
        hits = sorted({r for r, _d in _references(endpoint) if _matches(r, _NETWORK_LIBS)})
        if hits:
            stray[path] = hits
    assert not stray, f"GET routes reach the network without @token_outbound: {stray}"


async def _stub_unflagged_tool() -> Any:
    # Reaches httpx only two app.* calls down (preflight -> mirror probe).
    return await preflight_run_all(None)  # type: ignore[arg-type]


def test_the_scan_follows_helpers_into_other_modules() -> None:
    """Negative control: a function reaching the network only through a
    helper in another module is still caught."""
    assert any(r.startswith("httpx") for r in _reaches_outbound_helper(_stub_unflagged_tool))


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
async def test_unrestricted_token_keeps_outbound_mcp_tools(
    client: AsyncClient,
    db_session: AsyncSession,
    no_real_ping: list[str],
) -> None:
    raw = await _token(db_session, [])
    listed = await _listed(client, raw)
    assert "network_ping" in listed
    assert "find_dns_zone_drift" in listed
    resp = await _mcp(
        client, raw, "tools/call", {"name": "network_ping", "arguments": {"host": "192.0.2.1"}}
    )
    assert "error" not in resp, resp
    assert resp["result"]["isError"] is False
    assert no_real_ping == ["192.0.2.1"]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "scopes",
    [
        ["read", "ipam:write"],
        ["read", "dns:write"],
        ["read", "ipam:write", "dns:write", "dhcp:write"],
    ],
)
async def test_a_write_scope_does_not_unlock_probes_over_mcp(
    client: AsyncClient,
    db_session: AsyncSession,
    no_real_ping: list[str],
    scopes: list[str],
) -> None:
    """REST refuses every one of these tokens ``POST /tools/ping`` (no write
    scope covers ``/tools``), so MCP — which they reach only through
    ``read`` — must too."""
    raw = await _token(db_session, scopes)
    assert (
        await client.post("/api/v1/tools/ping", json={"host": "192.0.2.1"}, headers=_h(raw))
    ).status_code == 403
    listed = await _listed(client, raw)
    assert "network_ping" not in listed
    assert "lookup_whois_ip" not in listed
    resp = await _mcp(
        client, raw, "tools/call", {"name": "network_ping", "arguments": {"host": "192.0.2.1"}}
    )
    assert "error" in resp, resp
    assert no_real_ping == []
    # Drift follows REST: ``GET /dns/.../drift`` admits dns:write, not ipam:write.
    assert ("find_dns_zone_drift" in listed) == ("dns:write" in scopes)


@pytest.mark.asyncio
async def test_a_write_only_token_still_cannot_reach_mcp(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """MCP is admitted only by ``read``; a write-only token is refused on
    both verbs, as on main."""
    raw = await _token(db_session, ["ipam:write", "dns:write", "dhcp:write"])
    assert (await client.get("/api/v1/ai/mcp", headers=_h(raw))).status_code == 403
    r = await client.post(
        "/api/v1/ai/mcp",
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
        headers=_h(raw),
    )
    assert r.status_code == 403


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
