"""#1537 — Azure DNS + Google Cloud DNS zone convergence against the REAL SDKs.

The per-driver suites stub the SDK error classes, so they can only prove
the driver matches the names the stubs were given. These tests drive the
installed ``azure-mgmt-dns`` / ``azure-core`` and ``google-cloud-dns`` /
``google-api-core`` clients end to end, with only the HTTP layer faked:
the request goes through the SDK's own serialisation and the response
through its own error mapping. That is what pins

* that ``ZonesOperations.create_or_update`` really sends ``If-None-Match: *``
  and that a 412 reaches the driver as ``HttpResponseError.status_code ==
  412``, and a 404 on delete as ``ResourceNotFoundError``;
* that a Cloud DNS 409 / 404 raises ``google.api_core.exceptions.Conflict``
  / ``NotFound`` (``google.cloud.exceptions`` re-exports those), which is
  what ``googledns._cause_is`` matches by name.

Skipped when an SDK is absent, so a slim image does not fail here.
"""

from __future__ import annotations

import io
import json
from types import SimpleNamespace
from typing import Any

import pytest

from app.drivers.dns._cloud_base import CloudDNSError

_SERVER = SimpleNamespace(id="srv-1", name="cloud")


# ── Azure ──────────────────────────────────────────────────────────────────


def _azure_client(statuses: list[int], seen: list[Any]) -> Any:
    """A real ``DnsManagementClient`` whose transport answers ``statuses``."""
    pytest.importorskip("azure.mgmt.dns")
    import requests  # noqa: PLC0415
    from azure.core.credentials import AccessToken, AccessTokenInfo  # noqa: PLC0415
    from azure.core.pipeline.transport import HttpTransport  # noqa: PLC0415
    from azure.core.rest._requests_basic import (  # noqa: PLC0415
        RestRequestsTransportResponse,
    )
    from azure.mgmt.dns import DnsManagementClient  # noqa: PLC0415

    class _Cred:
        def get_token(self, *a: Any, **k: Any) -> AccessToken:
            return AccessToken("t", 9_999_999_999)

        def get_token_info(self, *a: Any, **k: Any) -> AccessTokenInfo:
            return AccessTokenInfo("t", 9_999_999_999)

    class _Transport(HttpTransport):
        def __enter__(self) -> _Transport:
            return self

        def __exit__(self, *a: Any) -> None:
            return None

        def open(self) -> None:
            return None

        def close(self) -> None:
            return None

        def send(self, request: Any, **kw: Any) -> Any:
            seen.append(request)
            status = statuses.pop(0)
            body = (
                json.dumps({"error": {"code": f"E{status}", "message": f"HTTP {status}"}})
                if status >= 400
                else json.dumps({"name": "z", "location": "global"})
            ).encode()
            resp = requests.Response()
            resp.status_code = status
            resp.reason = "X"
            resp.headers["Content-Type"] = "application/json"
            resp._content = body
            resp.raw = io.BytesIO(body)
            return RestRequestsTransportResponse(request=request, internal_response=resp)

    return DnsManagementClient(_Cred(), "sub", transport=_Transport())


_AZ_CREDS = {
    "tenant_id": "t",
    "client_id": "c",
    "client_secret": "s",
    "subscription_id": "sub",
    "resource_group": "rg",
}


def _azure_driver(monkeypatch: pytest.MonkeyPatch, client: Any) -> Any:
    from app.drivers.dns.azuredns import AzureDNSDriver  # noqa: PLC0415

    driver = AzureDNSDriver()
    monkeypatch.setattr(driver, "_client", lambda creds: client)
    return driver


async def test_azure_create_sends_if_none_match_and_412_means_exists(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: list[Any] = []
    driver = _azure_driver(monkeypatch, _azure_client([412], seen))
    changed = await driver._apply_zone(
        _SERVER, dict(_AZ_CREDS), SimpleNamespace(name="a.example.com."), "create"
    )
    assert changed is False
    assert seen[0].method == "PUT"
    assert seen[0].headers.get("If-None-Match") == "*"


async def test_azure_create_201_is_a_change(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[Any] = []
    driver = _azure_driver(monkeypatch, _azure_client([201], seen))
    changed = await driver._apply_zone(
        _SERVER, dict(_AZ_CREDS), SimpleNamespace(name="a.example.com."), "create"
    )
    assert changed is True


@pytest.mark.parametrize("status", [401, 403, 409, 429, 500])
async def test_azure_create_other_statuses_raise(
    monkeypatch: pytest.MonkeyPatch, status: int
) -> None:
    driver = _azure_driver(monkeypatch, _azure_client([status], []))
    with pytest.raises(CloudDNSError):
        await driver._apply_zone(
            _SERVER, dict(_AZ_CREDS), SimpleNamespace(name="a.example.com."), "create"
        )


async def test_azure_delete_404_is_already_gone(monkeypatch: pytest.MonkeyPatch) -> None:
    driver = _azure_driver(monkeypatch, _azure_client([404], []))
    changed = await driver._apply_zone(
        _SERVER, dict(_AZ_CREDS), SimpleNamespace(name="a.example.com."), "delete"
    )
    assert changed is False


@pytest.mark.parametrize("status", [200, 204])
async def test_azure_delete_success_is_a_change(
    monkeypatch: pytest.MonkeyPatch, status: int
) -> None:
    """ARM answers 204 for a DELETE of a resource that does not exist, so
    an absent zone can also read as a change here — harmless: the caller's
    compensation then re-creates a zone the DB still holds."""
    driver = _azure_driver(monkeypatch, _azure_client([status], []))
    changed = await driver._apply_zone(
        _SERVER, dict(_AZ_CREDS), SimpleNamespace(name="a.example.com."), "delete"
    )
    assert changed is True


@pytest.mark.parametrize("status", [401, 403, 409, 429, 500])
async def test_azure_delete_other_statuses_raise(
    monkeypatch: pytest.MonkeyPatch, status: int
) -> None:
    driver = _azure_driver(monkeypatch, _azure_client([status], []))
    with pytest.raises(CloudDNSError):
        await driver._apply_zone(
            _SERVER, dict(_AZ_CREDS), SimpleNamespace(name="a.example.com."), "delete"
        )


# ── Google Cloud DNS ───────────────────────────────────────────────────────


class _FakeSession:
    """Stands in for the ``requests`` session ``google.cloud.dns`` sends on.

    ``routes`` maps ``(METHOD, path-suffix)`` to a list of
    ``(status, json-body)`` replies, popped in order.
    """

    def __init__(self, routes: dict[tuple[str, str], list[tuple[int, Any]]]) -> None:
        self.routes = routes
        self.calls: list[tuple[str, str]] = []

    def request(self, *, url: str, method: str, **kw: Any) -> Any:
        import requests  # noqa: PLC0415

        path = url.split("?", 1)[0]
        self.calls.append((method, path))
        for (m, suffix), replies in self.routes.items():
            if m == method and path.endswith(suffix) and replies:
                status, body = replies.pop(0)
                break
        else:
            raise AssertionError(f"unexpected {method} {url}")
        resp = requests.Response()
        resp.status_code = status
        resp.headers["Content-Type"] = "application/json"
        resp._content = json.dumps(body).encode()
        resp.request = requests.Request(method, url).prepare()
        return resp


def _gerr(status: int, reason: str) -> tuple[int, Any]:
    return (
        status,
        {"error": {"code": status, "message": reason, "errors": [{"reason": reason}]}},
    )


def _gzone(slug: str, dns_name: str) -> dict[str, Any]:
    return {"kind": "dns#managedZone", "name": slug, "dnsName": dns_name, "id": "1"}


def _google_driver(monkeypatch: pytest.MonkeyPatch, session: _FakeSession) -> Any:
    pytest.importorskip("google.cloud.dns")
    from google.auth.credentials import AnonymousCredentials  # noqa: PLC0415
    from google.cloud import dns  # noqa: PLC0415

    from app.drivers.dns.googledns import GoogleCloudDNSDriver  # noqa: PLC0415

    client = dns.Client(project="proj", credentials=AnonymousCredentials(), _http=session)
    driver = GoogleCloudDNSDriver()
    monkeypatch.setattr(driver, "_client", lambda creds: client)
    return driver


_G_CREDS = {"service_account_json": "{}", "project_id": "proj"}


def test_google_sdk_raises_conflict_and_notfound_classes() -> None:
    """The classes ``_cause_is`` names are the ones the SDK really raises."""
    pytest.importorskip("google.cloud.dns")
    from google.api_core import exceptions as gx  # noqa: PLC0415
    from google.cloud import exceptions as gce  # noqa: PLC0415

    assert gce.Conflict is gx.Conflict
    assert gce.NotFound is gx.NotFound
    assert issubclass(gx.Conflict, gx.GoogleAPICallError)
    assert issubclass(gx.NotFound, gx.GoogleAPICallError)


async def test_google_create_409_with_matching_dns_name_means_exists(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = _FakeSession(
        {
            ("POST", "/managedZones"): [_gerr(409, "alreadyExists")],
            ("GET", "/managedZones"): [
                (200, {"managedZones": [_gzone("new-example-com", "new.example.com.")]})
            ],
        }
    )
    driver = _google_driver(monkeypatch, session)
    changed = await driver._apply_zone(
        _SERVER, _G_CREDS, SimpleNamespace(name="new.example.com."), "create"
    )
    assert changed is False


async def test_google_create_409_on_a_slug_another_domain_holds_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``a-b.com`` and ``a.b.com`` share the slug ``a-b-com``: a 409 there
    is not "already exists" for us, and the provider's 409 is reported."""
    session = _FakeSession(
        {
            ("POST", "/managedZones"): [_gerr(409, "alreadyExists")],
            ("GET", "/managedZones"): [(200, {"managedZones": [_gzone("a-b-com", "a.b.com.")]})],
        }
    )
    driver = _google_driver(monkeypatch, session)
    with pytest.raises(CloudDNSError, match="create_zone failed"):
        await driver._apply_zone(_SERVER, _G_CREDS, SimpleNamespace(name="a-b.com."), "create")


@pytest.mark.parametrize(("status", "reason"), [(403, "forbidden"), (429, "rateLimitExceeded")])
async def test_google_create_other_errors_raise(
    monkeypatch: pytest.MonkeyPatch, status: int, reason: str
) -> None:
    session = _FakeSession({("POST", "/managedZones"): [_gerr(status, reason)]})
    driver = _google_driver(monkeypatch, session)
    with pytest.raises(CloudDNSError):
        await driver._apply_zone(
            _SERVER, _G_CREDS, SimpleNamespace(name="new.example.com."), "create"
        )


async def test_google_create_201_is_a_change(monkeypatch: pytest.MonkeyPatch) -> None:
    session = _FakeSession(
        {("POST", "/managedZones"): [(200, _gzone("new-example-com", "new.example.com."))]}
    )
    driver = _google_driver(monkeypatch, session)
    changed = await driver._apply_zone(
        _SERVER, _G_CREDS, SimpleNamespace(name="new.example.com."), "create"
    )
    assert changed is True


async def test_google_delete_404_from_the_delete_call_means_gone(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = _FakeSession(
        {
            ("GET", "/managedZones"): [
                (200, {"managedZones": [_gzone("gone-example-com", "gone.example.com.")]})
            ],
            ("DELETE", "/managedZones/gone-example-com"): [_gerr(404, "notFound")],
        }
    )
    driver = _google_driver(monkeypatch, session)
    changed = await driver._apply_zone(
        _SERVER, _G_CREDS, SimpleNamespace(name="gone.example.com."), "delete"
    )
    assert changed is False


@pytest.mark.parametrize(
    ("status", "reason"), [(400, "containerNotEmpty"), (403, "forbidden"), (500, "backendError")]
)
async def test_google_delete_other_errors_raise(
    monkeypatch: pytest.MonkeyPatch, status: int, reason: str
) -> None:
    session = _FakeSession(
        {
            ("GET", "/managedZones"): [
                (200, {"managedZones": [_gzone("gone-example-com", "gone.example.com.")]})
            ],
            ("DELETE", "/managedZones/gone-example-com"): [_gerr(status, reason)],
        }
    )
    driver = _google_driver(monkeypatch, session)
    with pytest.raises(CloudDNSError):
        await driver._apply_zone(
            _SERVER,
            _G_CREDS,
            SimpleNamespace(name="gone.example.com."),
            "delete",
        )
