import re
import time

from prometheus_client import CONTENT_TYPE_LATEST, Counter, Gauge, Histogram, generate_latest
from starlette.concurrency import run_in_threadpool
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

# API metrics
REQUEST_COUNT = Counter(
    "spatiumddi_api_requests_total",
    "Total HTTP requests",
    ["method", "path_template", "status_code"],
)
REQUEST_DURATION = Histogram(
    "spatiumddi_api_request_duration_seconds",
    "HTTP request duration in seconds",
    ["method", "path_template"],
)
ACTIVE_REQUESTS = Gauge(
    "spatiumddi_api_active_requests",
    "Number of currently active HTTP requests",
)

# Auth metrics
AUTH_LOGIN_COUNT = Counter(
    "spatiumddi_auth_login_total",
    "Total login attempts",
    ["method", "result"],
)
AUTH_TOKEN_USAGE = Counter(
    "spatiumddi_auth_token_usage_total",
    "API token usage count",
    ["scope"],
)

# #1111 — the DNS agent config long-poll serves a bundle rendered once per
# (server, watermark) and stored. How it answered, and how often the
# migration-release inline fallback had to build one in the api itself.
# Worker renders are counted on the server row (``bundle_render_count``):
# the worker is another process and this registry is the api's.
AGENT_BUNDLE_SERVED = Counter(
    "spatiumddi_agent_bundle_served_total",
    "Agent config long-poll answers by outcome (full / not_modified)",
    ["family", "outcome"],
)
AGENT_BUNDLE_INLINE_RENDERS = Counter(
    "spatiumddi_agent_bundle_inline_renders_total",
    "Agent config bundles the api rendered inline (migration-release fallback)",
    ["family"],
)

# #1051 — the ``path_template`` value for a request no route claimed (a 404,
# or a path the router never saw). ONE constant bucket, never the raw path:
# the label set must stay bounded by the route table, not by what clients
# send.
UNMATCHED_PATH = "<unmatched>"


def path_template_label(request: Request) -> str:
    """The matched route's template — ``/api/v1/ipam/subnets/{subnet_id}`` —
    or ``UNMATCHED_PATH``.

    #1051 — this must be read AFTER the router has run. ``scope["route"]`` is
    written during routing, so a middleware that reads it before ``call_next``
    always sees nothing and falls back to the raw request path. That is what
    shipped: every distinct object URL (``/subnets/<uuid>``) became its own
    label set — a Counter series plus an 18-line Histogram family — and the
    registry grew without bound for the life of the process. Rendering it then
    took seconds; see ``metrics_endpoint`` for what that did to the event loop.

    The include prefixes are recovered from the request path rather than read
    off the route: FastAPI 0.115 flattened ``include_router(prefix=...)`` into
    the route's ``path_format``, FastAPI 0.141 keeps included routers nested
    and hands the middleware the ORIGINAL route, whose template lacks every
    prefix (``/accounts/{account_id}`` for ``/api/v1/acme/accounts/<id>``).
    The route's own regex matches exactly the tail the route owns; whatever
    stands before it is the include prefix, and any path parameter that lives
    in that prefix is written back as its ``{name}``. The label is therefore
    the same string on both FastAPI generations, and bounded by the route
    table on both.
    """
    route = request.scope.get("route")
    template = getattr(route, "path_format", None) or getattr(route, "path", None)
    if not isinstance(template, str) or not template:
        return UNMATCHED_PATH
    prefix = _include_prefix(route, request.scope.get("path") or "")
    if not prefix:
        return template
    return _template_prefix(prefix, request.scope.get("path_params") or {}, route) + template


def _include_prefix(route: object, path: str) -> str:
    """The part of ``path`` that stands before the segment the route's regex
    owns — the ``include_router`` prefixes — or ``""``."""
    regex = getattr(route, "path_regex", None)
    pattern = getattr(regex, "pattern", None)
    if not isinstance(pattern, str) or not path:
        return ""
    if pattern.startswith("^"):
        pattern = pattern[1:]
    try:
        tail = re.compile(pattern).search(path)
    except re.error:
        return ""
    if tail is None or tail.start() == 0:
        return ""
    return path[: tail.start()]


def _template_prefix(prefix: str, path_params: dict, route: object) -> str:
    """Write the path parameters that live in the include prefix back as
    ``{name}`` so a parametrised prefix (``/tenants/{tenant_id}``) stays one
    label. Parameters the route's own regex consumed are never in the prefix
    and are left alone."""
    convertors = getattr(route, "param_convertors", None) or {}
    prefix_params = {
        name: str(value) for name, value in path_params.items() if name not in convertors
    }
    if not prefix_params:
        return prefix
    by_value = {value: name for name, value in prefix_params.items() if value}
    segments = prefix.split("/")
    return "/".join(
        "{" + by_value[segment] + "}" if segment in by_value else segment for segment in segments
    )


class PrometheusMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: object) -> Response:
        # Skip metrics endpoint itself to avoid recursion
        if request.url.path == "/metrics":
            return await call_next(request)  # type: ignore[arg-type]

        method = request.method
        ACTIVE_REQUESTS.inc()
        start = time.perf_counter()
        status_code = 500  # fallback if call_next raises

        try:
            response: Response = await call_next(request)  # type: ignore[arg-type]
            status_code = response.status_code
            return response
        finally:
            duration = time.perf_counter() - start
            ACTIVE_REQUESTS.dec()
            # #1051 — resolved here, after routing, so it is the template and
            # the label cardinality is bounded by the route table.
            path_label = path_template_label(request)
            REQUEST_COUNT.labels(
                method=method,
                path_template=path_label,
                status_code=status_code,
            ).inc()
            REQUEST_DURATION.labels(method=method, path_template=path_label).observe(duration)


async def metrics_endpoint(request: Request) -> Response:
    """Prometheus scrape endpoint at /metrics.

    #1051 — rendered in a worker thread, not on the event loop.
    ``generate_latest`` is pure Python and walks every series in the
    registry. The appliance scrapes this endpoint from its own console every
    ~13 s (``spatium-console``); with the label leak above, each scrape came
    to hold the single uvicorn event loop for 3-8 s — measured live on
    2026-09-10, 81-83 % of the loop's samples inside this handler while
    ``/health/live`` sat unanswered past the kubelet's 5 s budget. Off the
    loop the render still costs the same CPU, but the loop keeps serving the
    probes and the requests between GIL slices instead of going dark for the
    duration.
    """
    data = await run_in_threadpool(generate_latest)
    return Response(content=data, media_type=CONTENT_TYPE_LATEST)
