"""Shared HTTP client for the seeder one-shots (docs §7.5 clean-appliance lifecycle).

Thin wrapper over ``httpx.Client`` carrying the contract conventions every seeder
script needs:

* base URL from ``manifest.target.api_base`` (e.g. ``https://10.20.0.10/api``);
* ``verify=False`` for the appliance self-signed cert (or ``SPDDI_PERF_CA_BUNDLE``);
* ``Authorization: Bearer <token>`` where the token comes from the env var NAMED in
  the manifest (``observability.superadmin_token_env``, default ``SPDDI_PERF_ADMIN_TOKEN``).
  No secret is ever hard-coded (non-negotiable #6).

Login fallback: if the token env var is unset, we POST ``/auth/login`` with
credentials from ``SPDDI_PERF_ADMIN_USER`` / ``SPDDI_PERF_ADMIN_PASSWORD`` (also
env-only). This lets a fresh-from-snapshot appliance be seeded with admin/admin
without baking a long-lived token, while production runs supply a token whose
lifetime ≥ run length (§7.6.6).

Grounding (real backend routes, cited file:line):
* ``POST /auth/login`` → ``{access_token, refresh_token, ...}``
  — backend/app/api/v1/auth/router.py:452 (LoginRequest {username, password}:94).
* Bearer scheme — backend/app/api/deps.py:20,128 (HTTPBearer).
"""

from __future__ import annotations

import os
from typing import Any

import httpx

from spddi_perf.logging_util import get_logger
from spddi_perf.manifest import Manifest

# Optional env-var names for the login fallback (never the secrets themselves).
ENV_ADMIN_USER = "SPDDI_PERF_ADMIN_USER"
ENV_ADMIN_PASSWORD = "SPDDI_PERF_ADMIN_PASSWORD"
ENV_CA_BUNDLE = "SPDDI_PERF_CA_BUNDLE"


def _verify_arg() -> Any:
    """``verify=`` for httpx: a CA bundle path if pinned, else False (self-signed)."""
    bundle = os.environ.get(ENV_CA_BUNDLE)
    return bundle if bundle else False


class ApiError(RuntimeError):
    """Raised on a non-2xx response, carrying status + body for the caller's log.

    ``retry_after`` is the response's ``Retry-After`` header as sent, or None:
    the API's 503 for a database that did not answer in time and nginx's
    502/504 for an api it could not reach both carry one (#2879).
    """

    def __init__(
        self,
        method: str,
        url: str,
        status_code: int,
        body: str,
        retry_after: str | None = None,
    ) -> None:
        super().__init__(f"{method} {url} -> {status_code}: {body[:500]}")
        self.status_code = status_code
        self.body = body
        self.retry_after = retry_after


class ApiClient:
    """Authenticated httpx client against ``target.api_base``.

    Use as a context manager so the underlying connection pool is closed::

        with ApiClient.from_manifest(m, run_id) as api:
            api.post("/ipam/spaces", json={...})
    """

    def __init__(
        self,
        base_url: str,
        token: str,
        *,
        run_id: str | None = None,
        timeout: float = 60.0,
    ) -> None:
        # api_base already ends in ``/api``; routes here are passed as ``/v1/...``
        # absolute paths, so normalise the join (strip a trailing slash).
        self.base_url = base_url.rstrip("/")
        self._token = token
        self.log = get_logger("spddi_perf.seeder.api", run_id=run_id)
        self._client = httpx.Client(
            base_url=self.base_url,
            verify=_verify_arg(),
            timeout=timeout,
            headers={"Authorization": f"Bearer {token}"},
        )

    # ---- construction ----
    @classmethod
    def from_manifest(cls, m: Manifest, *, run_id: str | None = None, timeout: float = 60.0) -> "ApiClient":
        """Build a client: prefer the env token, else log in for one."""
        token = cls.resolve_token(m, run_id=run_id)
        return cls(m.target.api_base, token, run_id=run_id, timeout=timeout)

    @staticmethod
    def resolve_token(m: Manifest, *, run_id: str | None = None) -> str:
        """Return a bearer token: the manifest-named env var, or a fresh login."""
        log = get_logger("spddi_perf.seeder.api", run_id=run_id)
        env_name = m.observability.superadmin_token_env
        token = os.environ.get(env_name)
        if token:
            log.info("using bearer token from env %s", env_name)
            return token

        user = os.environ.get(ENV_ADMIN_USER)
        pw = os.environ.get(ENV_ADMIN_PASSWORD)
        if not user or not pw:
            raise RuntimeError(
                f"No token in ${env_name} and no login fallback "
                f"(set ${ENV_ADMIN_USER} + ${ENV_ADMIN_PASSWORD})"
            )
        # POST /v1/auth/login — backend/app/api/v1/auth/router.py:452
        url = m.target.api_base.rstrip("/") + "/v1/auth/login"
        with httpx.Client(verify=_verify_arg(), timeout=30.0) as c:
            resp = c.post(url, json={"username": user, "password": pw})
        if resp.status_code != 200:
            raise ApiError("POST", url, resp.status_code, resp.text)
        data = resp.json()
        tok = data.get("access_token")
        if not tok:
            # mfa_required or force_password_change with no access_token
            raise RuntimeError(
                f"login for {user!r} returned no access_token "
                f"(mfa_required={data.get('mfa_required')}); seed with a "
                f"non-MFA superadmin or supply ${env_name}"
            )
        log.info("logged in as %s for a bearer token", user)
        return tok

    # ---- HTTP verbs (all paths are absolute, e.g. ``/v1/ipam/spaces``) ----
    def request(self, method: str, path: str, *, ok: tuple[int, ...] = (200, 201, 204), **kw: Any) -> httpx.Response:
        resp = self._client.request(method, path, **kw)
        if resp.status_code not in ok:
            raise ApiError(
                method, path, resp.status_code, resp.text, resp.headers.get("Retry-After")
            )
        return resp

    def get(self, path: str, *, ok: tuple[int, ...] = (200,), **kw: Any) -> httpx.Response:
        return self.request("GET", path, ok=ok, **kw)

    def post(self, path: str, *, ok: tuple[int, ...] = (200, 201, 204), **kw: Any) -> httpx.Response:
        return self.request("POST", path, ok=ok, **kw)

    def put(self, path: str, *, ok: tuple[int, ...] = (200, 201, 204), **kw: Any) -> httpx.Response:
        return self.request("PUT", path, ok=ok, **kw)

    def json(self, method: str, path: str, **kw: Any) -> Any:
        return self.request(method, path, **kw).json()

    def origin(self) -> str:
        """Scheme+host of the appliance (api_base minus the ``/api`` suffix).

        ``/health/*`` and ``/metrics/*`` are mounted at the backend root, NOT
        under ``/api/v1`` (backend/app/main.py mounts health with no prefix;
        the frontend nginx routes ``^/(health|metrics)`` straight to the api
        upstream — see charts/spatiumddi/templates/frontend-tls-config.yaml).
        So they live at the bare origin.
        """
        u = httpx.URL(self.base_url)
        host = f"{u.scheme}://{u.host}"
        if u.port:
            host = f"{host}:{u.port}"
        return host

    def get_root(self, path: str, *, ok: tuple[int, ...] = (200,), **kw: Any) -> httpx.Response:
        """GET an origin-relative path (for /health/*, /metrics/*) — no auth needed."""
        url = self.origin() + path
        resp = self._client.get(url, **kw)
        if resp.status_code not in ok:
            raise ApiError("GET", url, resp.status_code, resp.text)
        return resp

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "ApiClient":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()
