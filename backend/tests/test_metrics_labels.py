"""#1051 — request metrics are labelled by ROUTE TEMPLATE, never by raw path.

``PrometheusMiddleware`` used to read ``scope["route"]`` before ``call_next``,
i.e. before the router had run, so the ``path_template`` label was the raw
request path on every request: each distinct object URL became its own label
set and the registry grew without bound for the life of the process, until
the appliance's own ~13 s ``/metrics`` scrape held the event loop for seconds
and the kubelet's probes on that loop timed out. These tests pin the label to
the template (and unmatched paths to one bucket) with a throwaway app, so
they need no database — they read the process-global registry through the
metric objects themselves.
"""

from __future__ import annotations

import re

import pytest
from fastapi import APIRouter, FastAPI
from fastapi.testclient import TestClient

from app.config import settings
from app.metrics import (
    REQUEST_COUNT,
    UNMATCHED_PATH,
    PrometheusMiddleware,
    metrics_endpoint,
    path_template_label,
)

_TEMPLATE = "/_qa1051/items/{item_id}"


def _app() -> FastAPI:
    app = FastAPI()
    app.add_middleware(PrometheusMiddleware)

    @app.get(_TEMPLATE)
    async def _item(item_id: str) -> dict[str, str]:
        return {"item_id": item_id}

    app.add_route("/metrics", metrics_endpoint)
    return app


def _count(method: str, template: str, status: str) -> float:
    want = {"method": method, "path_template": template, "status_code": status}
    for metric in REQUEST_COUNT.collect():
        for sample in metric.samples:
            if sample.name.endswith("_total") and sample.labels == want:
                return float(sample.value)
    return 0.0


def _template_labels() -> set[str]:
    return {
        sample.labels.get("path_template", "")
        for metric in REQUEST_COUNT.collect()
        for sample in metric.samples
    }


def test_requests_are_labelled_by_the_route_template_not_the_raw_path() -> None:
    client = TestClient(_app())
    before = _count("GET", _TEMPLATE, "200")

    for item_id in ("a", "b", "c0ffee-4d3a-1051"):
        assert client.get(f"/_qa1051/items/{item_id}").status_code == 200

    assert _count("GET", _TEMPLATE, "200") == before + 3
    leaked = [v for v in _template_labels() if "/_qa1051/items/" in v and "{item_id}" not in v]
    assert leaked == [], leaked


def test_unmatched_paths_share_one_bucket() -> None:
    client = TestClient(_app())
    before = _count("GET", UNMATCHED_PATH, "404")

    for path in ("/_qa1051/no-such/1", "/_qa1051/no-such/2", "/_qa1051/nope"):
        assert client.get(path).status_code == 404

    assert _count("GET", UNMATCHED_PATH, "404") == before + 3
    leaked = [v for v in _template_labels() if "no-such" in v or "nope" in v]
    assert leaked == [], leaked


def test_metrics_endpoint_renders_and_does_not_count_itself(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # #1159 — the endpoint needs a bearer token now.
    monkeypatch.setattr(settings, "prometheus_metrics_token", "labels-test-token")
    client = TestClient(_app())
    before = _count("GET", "/metrics", "200")

    response = client.get("/metrics", headers={"Authorization": "Bearer labels-test-token"})

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/plain")
    assert b"spatiumddi_api_requests_total" in response.content
    assert _count("GET", "/metrics", "200") == before


def test_path_template_label_prefers_the_route_format() -> None:
    class _Route:
        path_format = "/things/{thing_id}"
        path = "/things/{thing_id:uuid}"
        path_regex = re.compile("^/things/(?P<thing_id>[^/]+)$")
        param_convertors = {"thing_id": object()}

    class _Req:
        scope = {
            "route": _Route(),
            "path": "/api/v1/things/3fa85f64-5717-4562-b3fc-2c963f66afa6",
            "path_params": {"thing_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6"},
        }

    # FastAPI >= 0.141 hands over the un-prefixed original route: the include
    # prefix is recovered from the request path, the parameter stays templated.
    assert path_template_label(_Req()) == "/api/v1/things/{thing_id}"  # type: ignore[arg-type]

    class _Flat:
        path_format = "/api/v1/things/{thing_id}"
        path = "/api/v1/things/{thing_id:uuid}"

    class _FlatReq:
        scope = {"route": _Flat(), "path": "/api/v1/things/abc"}

    # FastAPI 0.115 flattened the prefix into the route: nothing to recover.
    assert path_template_label(_FlatReq()) == "/api/v1/things/{thing_id}"  # type: ignore[arg-type]
    assert path_template_label(type("R", (), {"scope": {}})()) == UNMATCHED_PATH  # type: ignore[arg-type]


def _prefixed_app() -> FastAPI:
    """The product's shape: routers nested under include prefixes, two of
    them sharing a relative path, one path converter, one parametrised
    prefix — every label must carry its prefixes and stay one per route."""
    app = FastAPI()
    app.add_middleware(PrometheusMiddleware)

    accounts = APIRouter()

    @accounts.get("/accounts/{account_id}")
    async def _account(account_id: str) -> dict[str, str]:
        return {"account_id": account_id}

    files = APIRouter()

    @files.get("/files/{name:path}")
    async def _file(name: str) -> dict[str, str]:
        return {"name": name}

    tenants = APIRouter()

    @tenants.get("/keys/{key_id}")
    async def _key(tenant_id: str, key_id: str) -> dict[str, str]:
        return {"tenant_id": tenant_id, "key_id": key_id}

    v1 = APIRouter()
    v1.include_router(accounts, prefix="/_qa1051p/acme")
    v1.include_router(accounts, prefix="/_qa1051p/billing")
    v1.include_router(files, prefix="/_qa1051p")
    v1.include_router(tenants, prefix="/_qa1051p/tenants/{tenant_id}")
    app.include_router(v1, prefix="/api/v1")
    app.add_route("/metrics", metrics_endpoint)
    return app


def test_include_router_prefixes_are_part_of_the_label() -> None:
    client = TestClient(_prefixed_app())
    acme = "/api/v1/_qa1051p/acme/accounts/{account_id}"
    billing = "/api/v1/_qa1051p/billing/accounts/{account_id}"
    before_acme, before_billing = _count("GET", acme, "200"), _count("GET", billing, "200")

    for account_id in ("a1", "b2", "3fa85f64-5717-4562-b3fc-2c963f66afa6"):
        assert client.get(f"/api/v1/_qa1051p/acme/accounts/{account_id}").status_code == 200
    assert client.get("/api/v1/_qa1051p/billing/accounts/z9").status_code == 200

    assert _count("GET", acme, "200") == before_acme + 3
    assert _count("GET", billing, "200") == before_billing + 1
    leaked = [
        v
        for v in _template_labels()
        if "_qa1051p" in v and "accounts" in v and "{account_id}" not in v
    ]
    assert leaked == [], leaked


def test_path_converter_and_parametrised_prefix_stay_one_label_each() -> None:
    client = TestClient(_prefixed_app())
    files = "/api/v1/_qa1051p/files/{name}"
    keys = "/api/v1/_qa1051p/tenants/{tenant_id}/keys/{key_id}"
    before_files, before_keys = _count("GET", files, "200"), _count("GET", keys, "200")

    assert client.get("/api/v1/_qa1051p/files/a/b/c.txt").status_code == 200
    assert client.get("/api/v1/_qa1051p/files/d").status_code == 200
    assert client.get("/api/v1/_qa1051p/tenants/acme-corp/keys/k1").status_code == 200
    assert client.get("/api/v1/_qa1051p/tenants/globex/keys/k2").status_code == 200

    assert _count("GET", files, "200") == before_files + 2
    assert _count("GET", keys, "200") == before_keys + 2
    leaked = [
        v
        for v in _template_labels()
        if "_qa1051p" in v and ("acme-corp" in v or "globex" in v or "c.txt" in v)
    ]
    assert leaked == [], leaked
