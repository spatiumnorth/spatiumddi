"""Copilot / MCP network tools spend the same per-user budget as ``/tools``.

The ``/api/v1/tools/*`` routes cap each user at a fixed number of probe
calls per window (``app.services.nettools.throttle``). The copilot tools
that run the same probes declare the matching bucket via ``rate_limit=``
and ``ToolRegistry.call`` spends it, so a user has ONE budget whichever
surface they drive the tools from. These tests use an in-memory Redis
stand-in so the counter is real but nothing is sent on the network.
"""

from __future__ import annotations

import ast
import importlib
import inspect
import json
import textwrap
import uuid
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.ai import mcp as mcp_mod
from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.services import feature_modules
from app.services.ai.tools import REGISTRY
from app.services.ai.tools.base import Tool, ToolRegistry
from app.services.nettools import budgets
from app.services.nettools.schemas import CommandResult

# The module, not the ``router`` object the package re-exports under the
# same name.
tools_router_mod = importlib.import_module("app.api.v1.tools.router")

_REDIS = "app.services.nettools.throttle.make_async_redis"


class _CountingRedis:
    """Just enough of the async Redis client for the throttle: a shared
    counter script, so successive calls really accumulate."""

    def __init__(self) -> None:
        self.counts: dict[str, int] = {}

    def __call__(self, *_a: Any, **_kw: Any) -> _CountingRedis:
        return self

    async def eval(self, _script: str, _numkeys: int, key: str, *_args: Any) -> int:
        # The throttle's INCR-and-open-window script.
        self.counts[key] = self.counts.get(key, 0) + 1
        return self.counts[key]

    async def aclose(self) -> None:
        return None


def _redis_down(*_a: Any, **_kw: Any) -> Any:
    raise ConnectionError("redis unreachable")


@pytest.fixture(autouse=True)
def _reset_module_cache():
    feature_modules.invalidate_cache()
    yield
    feature_modules.invalidate_cache()


@pytest.fixture
def small_budget(monkeypatch: pytest.MonkeyPatch) -> int:
    """Shrink both windows so a test can spend them in a few calls. The
    throttle reads the same dict object, so REST sees the change too."""
    monkeypatch.setitem(budgets.BUDGETS, "default", 2)
    monkeypatch.setitem(budgets.BUDGETS, "offprem", 1)
    return 2


async def _admin(db: AsyncSession) -> tuple[User, str]:
    # Superadmins are not exempt from the budget, so one keeps the
    # permission setup out of the way.
    u = User(
        username=f"rl-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="Rate limit",
        hashed_password=hash_password("x"),
        is_superadmin=True,
        is_active=True,
    )
    db.add(u)
    await db.flush()
    return u, create_access_token(str(u.id))


async def _mcp_call(db: AsyncSession, user: User, name: str, args: dict) -> dict:
    frame = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": name, "arguments": args},
    }
    return await mcp_mod._dispatch_one(frame, db, user)


def _result(resp: dict) -> tuple[bool, Any]:
    assert "result" in resp, resp
    return bool(resp["result"].get("isError")), json.loads(resp["result"]["content"][0]["text"])


def _ping_ok() -> CommandResult:
    return CommandResult(tool="ping", argv=["ping"], available=True, exit_code=0, stdout="ok")


# ── the budget applies over MCP ────────────────────────────────────────────


@pytest.mark.asyncio
async def test_mcp_network_tool_is_refused_once_the_budget_is_spent(
    db_session: AsyncSession, small_budget: int
) -> None:
    user, _ = await _admin(db_session)
    runner = AsyncMock(return_value=_ping_ok())
    with patch(_REDIS, _CountingRedis()), patch("app.services.ai.tools.nettools.run_ping", runner):
        for _ in range(small_budget):
            is_error, body = _result(
                await _mcp_call(db_session, user, "network_ping", {"host": "192.0.2.1"})
            )
            assert not is_error and body["exit_code"] == 0
        is_error, body = _result(
            await _mcp_call(db_session, user, "network_ping", {"host": "192.0.2.1"})
        )

    assert is_error, body
    assert body["rate_limited"] is True
    assert body["retry_after_seconds"] == budgets.WINDOW_SECONDS
    assert body["error"] == budgets.budget_exceeded_message("default")
    # The refused call never reached the runner.
    assert runner.await_count == small_budget


@pytest.mark.asyncio
async def test_ping_host_and_tls_cert_check_spend_the_budget_too(
    db_session: AsyncSession, small_budget: int
) -> None:
    """The two older probe tools outside ``nettools.py`` are covered as well:
    a spent budget refuses them before they open a socket or a subprocess."""
    user, _ = await _admin(db_session)
    fake = _CountingRedis()
    fake.counts[budgets.budget_key("default", str(user.id))] = small_budget
    with (
        patch(_REDIS, fake),
        patch("asyncio.create_subprocess_exec", AsyncMock()) as spawn,
        patch("app.services.ai.tools.ops._resolve_allowed") as resolve,
    ):
        for name, args in (
            ("ping_host", {"target": "192.0.2.1"}),
            ("tls_cert_check", {"host": "192.0.2.1", "port": 443}),
        ):
            out = await REGISTRY.call(name, args, db=db_session, user=user)
            assert out["rate_limited"] is True, (name, out)
    spawn.assert_not_called()
    resolve.assert_not_called()


# ── one budget across both surfaces ────────────────────────────────────────


@pytest.mark.asyncio
async def test_rest_and_mcp_calls_share_one_budget(
    client: AsyncClient, db_session: AsyncSession, small_budget: int
) -> None:
    user, token = await _admin(db_session)
    with (
        patch(_REDIS, _CountingRedis()),
        patch.object(tools_router_mod, "run_ping", AsyncMock(return_value=_ping_ok())),
        patch("app.services.ai.tools.nettools.run_ping", AsyncMock(return_value=_ping_ok())),
    ):
        for _ in range(small_budget):
            r = await client.post(
                "/api/v1/tools/ping",
                json={"host": "192.0.2.1"},
                headers={"Authorization": f"Bearer {token}"},
            )
            assert r.status_code == 200, r.text
        # The REST calls spent the window, so the copilot is refused …
        is_error, body = _result(
            await _mcp_call(db_session, user, "network_ping", {"host": "192.0.2.1"})
        )
        assert is_error and body["rate_limited"] is True, body
        # … and the copilot's attempt counted too: REST is still refused.
        r = await client.post(
            "/api/v1/tools/ping",
            json={"host": "192.0.2.1"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert r.status_code == 429, r.text
        assert r.json()["detail"] == budgets.budget_exceeded_message("default")


@pytest.mark.asyncio
async def test_mcp_calls_spend_the_budget_rest_then_sees(
    client: AsyncClient, db_session: AsyncSession, small_budget: int
) -> None:
    user, token = await _admin(db_session)
    with (
        patch(_REDIS, _CountingRedis()),
        patch.object(tools_router_mod, "run_ping", AsyncMock(return_value=_ping_ok())),
        patch("app.services.ai.tools.nettools.run_ping", AsyncMock(return_value=_ping_ok())),
    ):
        for _ in range(small_budget):
            is_error, _body = _result(
                await _mcp_call(db_session, user, "network_ping", {"host": "192.0.2.1"})
            )
            assert not is_error
        r = await client.post(
            "/api/v1/tools/ping",
            json={"host": "192.0.2.1"},
            headers={"Authorization": f"Bearer {token}"},
        )
    assert r.status_code == 429, r.text


@pytest.mark.asyncio
async def test_offprem_tools_use_their_own_bucket(
    db_session: AsyncSession, small_budget: int
) -> None:
    """Spending the on-prem window does not refuse an off-prem lookup, and
    the off-prem window refuses on its own count — the REST split."""
    user, _ = await _admin(db_session)
    fake = _CountingRedis()
    fake.counts[budgets.budget_key("default", str(user.id))] = small_budget
    lookup = AsyncMock(return_value={"holder_org": "Example"})
    with patch(_REDIS, fake), patch("app.services.ai.tools.whois.lookup_ip", lookup):
        first = await REGISTRY.call(
            "lookup_whois_ip", {"address": "192.0.2.1"}, db=db_session, user=user
        )
        second = await REGISTRY.call(
            "lookup_whois_ip", {"address": "192.0.2.1"}, db=db_session, user=user
        )
    assert first == {"holder_org": "Example"}
    assert second["rate_limited"] is True
    assert second["error"] == budgets.budget_exceeded_message("offprem")
    assert lookup.await_count == 1


@pytest.mark.asyncio
async def test_redis_outage_fails_open_on_both_surfaces(
    client: AsyncClient, db_session: AsyncSession, small_budget: int
) -> None:
    """The REST throttle lets calls through when Redis is unreachable; the
    copilot must behave identically, not refuse and not raise."""
    user, token = await _admin(db_session)
    with (
        patch(_REDIS, _redis_down),
        patch.object(tools_router_mod, "run_ping", AsyncMock(return_value=_ping_ok())),
        patch("app.services.ai.tools.nettools.run_ping", AsyncMock(return_value=_ping_ok())),
    ):
        for _ in range(small_budget + 2):
            r = await client.post(
                "/api/v1/tools/ping",
                json={"host": "192.0.2.1"},
                headers={"Authorization": f"Bearer {token}"},
            )
            assert r.status_code == 200, r.text
            is_error, body = _result(
                await _mcp_call(db_session, user, "network_ping", {"host": "192.0.2.1"})
            )
            assert not is_error and body["exit_code"] == 0, body


@pytest.mark.asyncio
async def test_a_refused_call_spends_no_budget(db_session: AsyncSession) -> None:
    """The budget is spent only by a call that is going to run: a caller the
    tool's permission refuses, or arguments that fail validation, leave the
    counter where it was."""
    from app.services.ai.tools import ToolArgumentError, ToolPermissionDenied

    plain = User(
        username=f"rl-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="No tools",
        hashed_password=hash_password("x"),
        is_superadmin=False,
        is_active=True,
    )
    db_session.add(plain)
    await db_session.flush()
    await db_session.refresh(plain, ["groups"])
    admin, _ = await _admin(db_session)
    fake = _CountingRedis()
    with patch(_REDIS, fake):
        with pytest.raises(ToolPermissionDenied):
            await REGISTRY.call("network_ping", {"host": "192.0.2.1"}, db=db_session, user=plain)
        with pytest.raises(ToolArgumentError):
            await REGISTRY.call("network_ping", {}, db=db_session, user=admin)
    assert fake.counts == {}


# ── declarations ───────────────────────────────────────────────────────────

# Every copilot tool that runs a probe some ``/api/v1/tools/*`` route also
# runs, against that route. The tool must spend the route's bucket.
_TOOL_TO_REST_ROUTE = {
    "network_ping": "/ping",
    "ping_host": "/ping",
    "network_traceroute": "/traceroute",
    "network_dig": "/dig",
    "network_port_test": "/port-test",
    "network_tls_cert": "/tls-cert",
    "tls_cert_check": "/tls-cert",
    "lookup_mac_vendor": "/mac-vendor",
    "network_whois": "/whois",
    "forward_dns": "/dig",
    "reverse_dns": "/dig",
}

# ── what counts as sending traffic ─────────────────────────────────────────
#
# The guard below does not trust a list of tool names or a grep of the
# executor's own body: it walks every function the executor reaches inside
# ``app`` (called directly, passed to ``asyncio.to_thread`` / ``run_in_executor``,
# or imported inside the function body) and looks for these primitives in the
# resolved AST — names, not strings, so a docstring that mentions httpx does
# not count and a helper two calls down that opens a socket does.

# Attribute names that open a connection or send a packet whatever object
# they are called on (``loop.create_datagram_endpoint``, ``sock.sendto``).
_OUTBOUND_ATTRS = frozenset(
    {
        "create_subprocess_exec",
        "create_subprocess_shell",
        "open_connection",
        "create_connection",
        "create_datagram_endpoint",
        "sendto",
        "urlopen",
    }
)

# Dotted prefixes of a resolved module reference (``httpx.AsyncClient``,
# ``dns.resolver.Resolver``) or of the module an imported name came from.
_OUTBOUND_MODULES = (
    "httpx",
    "aiohttp",
    "requests",
    "urllib.request",
    "dns.resolver",
    "dns.query",
    "dns.asyncresolver",
    "dns.asyncquery",
    "socket.socket",
    "winrm",
    "pysnmp",
    "asyncssh",
    "paramiko",
)

# Tools that DO reach outbound code but deliberately spend no network-tool
# budget, each with the reason. The guard fails on any other tool that
# reaches outbound code without ``rate_limit=``, and on a stale entry here.
_SENDS_TRAFFIC_WITHOUT_A_BUDGET: dict[str, str] = {
    # Fixed public data providers (RIPEstat / PeeringDB), cached, and their
    # REST twins under /asns carry no network-tool budget either.
    "asn_announced_prefixes": "RIPEstat, cached; REST twin unbudgeted",
    "asn_ixp_presence": "PeeringDB, cached; REST twin unbudgeted",
    "asn_peering_profile": "PeeringDB, cached; REST twin unbudgeted",
    "prefix_origin": "RIPEstat, cached; REST twin unbudgeted",
    "prefix_routing_history": "RIPEstat, cached; REST twin unbudgeted",
    # Local infrastructure the control plane itself runs on, not a target
    # the caller chooses.
    "find_services": "local Docker socket / Kubernetes API, superadmin",
    "find_upgrade_preflight": "in-cluster slot-image mirror, superadmin",
    "find_cluster_metrics": "in-cluster CoreDNS probe, superadmin",
    "find_available_upgrade_images": "fixed release feed, superadmin",
    # A one-shot migration read of a source server the superadmin names;
    # its REST twin (/dns/import) carries no network-tool budget either.
    "find_dns_import_preview": "migration source pull, superadmin",
}

# Stated limit: the walk follows functions, not methods dispatched through
# a driver object (``get_driver(...).pull_zone_records``). The tools that
# reach the network that way (zone drift AXFR, the cutover parity pull)
# talk to servers the operator has configured, not to a target the caller
# names, and are outside this budget. ``propose_*`` tools send nothing; the
# operator's Apply runs the same operation as the REST route.


def _dotted(node: ast.AST) -> list[str] | None:
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if not isinstance(node, ast.Name):
        return None
    parts.append(node.id)
    return parts[::-1]


def _resolve(parts: list[str], scope: dict[str, Any]) -> tuple[Any, str | None]:
    """Resolve ``a.b.c`` against ``scope``; return the object (or None) and
    the best dotted module path for it."""
    obj = scope.get(parts[0], None)
    if obj is None:
        return None, None
    path = obj.__name__ if inspect.ismodule(obj) else getattr(obj, "__module__", None)
    if path and inspect.ismodule(obj):
        path = ".".join([path, *parts[1:]])
    for attr in parts[1:]:
        obj = getattr(obj, attr, None)
        if obj is None:
            break
    return obj, path


def _outbound_reach(fn: Any, seen: set[Any] | None = None) -> set[str]:
    """Every outbound primitive ``fn`` reaches through ``app`` code."""
    seen = set() if seen is None else seen
    fn = inspect.unwrap(fn)
    if fn in seen:
        return set()
    seen.add(fn)
    try:
        tree = ast.parse(textwrap.dedent(inspect.getsource(fn)))
    except (OSError, TypeError):
        return set()
    scope = dict(getattr(fn, "__globals__", {}))
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            for alias in node.names:
                try:
                    mod = importlib.import_module(node.module)
                except ImportError:
                    continue
                scope[alias.asname or alias.name] = getattr(mod, alias.name, None) or (
                    importlib.import_module(f"{node.module}.{alias.name}")
                )
        elif isinstance(node, ast.Import):
            for alias in node.names:
                root = alias.name.split(".")[0]
                scope[alias.asname or root] = importlib.import_module(
                    alias.name if alias.asname else root
                )
    hits: set[str] = set()
    where = f"{fn.__module__}.{fn.__qualname__}"
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and node.attr in _OUTBOUND_ATTRS:
            hits.add(f"{node.attr} in {where}")
        if not isinstance(node, (ast.Name, ast.Attribute)):
            continue
        parts = _dotted(node)
        if parts is None:
            continue
        obj, path = _resolve(parts, scope)
        if path and any(path == m or path.startswith(m + ".") for m in _OUTBOUND_MODULES):
            hits.add(f"{path} in {where}")
        if inspect.isfunction(obj) and (obj.__module__ or "").startswith("app."):
            hits |= _outbound_reach(obj, seen)
    return hits


def _route_bucket(path: str) -> str:
    for route in tools_router_mod.router.routes:
        if getattr(route, "path", None) != f"{tools_router_mod.router.prefix}{path}":
            continue
        for dep in route.dependant.dependencies:
            if not inspect.isfunction(dep.call):
                continue
            closure = inspect.getclosurevars(dep.call).nonlocals
            if "bucket" in closure:
                return closure["bucket"]
        raise AssertionError(f"REST route {path} has no rate-limit dependency")
    raise AssertionError(f"no REST route {path}")


@pytest.mark.parametrize(("tool_name", "path"), sorted(_TOOL_TO_REST_ROUTE.items()))
def test_tool_spends_the_same_bucket_as_its_rest_route(tool_name: str, path: str) -> None:
    tool = REGISTRY.get(tool_name)
    assert tool is not None, tool_name
    assert tool.rate_limit == _route_bucket(path), (tool_name, path)


def test_every_tool_that_sends_traffic_declares_a_budget() -> None:
    reach = {tool.name: _outbound_reach(tool.executor) for tool in REGISTRY.all()}
    missing = {
        name: sorted(hits)[:3]
        for name, hits in reach.items()
        if hits
        and REGISTRY.get(name).rate_limit is None
        and name not in _SENDS_TRAFFIC_WITHOUT_A_BUDGET
    }
    assert not missing, f"tools sending traffic without a rate_limit bucket: {missing}"
    # An exemption must still be needed, and must not contradict the tool.
    stale = [n for n in _SENDS_TRAFFIC_WITHOUT_A_BUDGET if not reach.get(n)]
    assert not stale, f"exempt tools that no longer send traffic (drop them): {stale}"
    budgeted = [n for n in _SENDS_TRAFFIC_WITHOUT_A_BUDGET if REGISTRY.get(n).rate_limit]
    assert not budgeted, f"exempt tools that declare a budget anyway: {budgeted}"


def test_the_traffic_walk_follows_helpers() -> None:
    """The guard's walker must see through helpers, or it proves nothing:
    each of these tools reaches its socket / subprocess / resolver only via
    another function (a runner, a helper handed to ``asyncio.to_thread``)."""
    for name in ("network_port_test", "network_ping", "tls_cert_check", "forward_dns"):
        tool = REGISTRY.get(name)
        assert tool is not None and _outbound_reach(tool.executor), name
    # … and a pure database read reaches nothing.
    tool = REGISTRY.get("list_dns_zones")
    assert tool is not None and not _outbound_reach(tool.executor)


def test_registration_rejects_an_unknown_bucket() -> None:
    from pydantic import BaseModel

    class _Args(BaseModel):
        pass

    async def _noop(db: Any, user: Any, args: Any) -> None:
        return None

    with pytest.raises(ValueError, match="rate_limit"):
        ToolRegistry().register(
            Tool(
                name="x",
                description="x",
                args_model=_Args,
                executor=_noop,
                permission="authenticated",
                rate_limit="unlimited",
            )
        )
