"""Version-aware InfluxDB write client (issue #889).

Three declared versions, **two** wire dialects:

===== ============================== ==============================
ver   endpoint                       auth
===== ============================== ==============================
v1    ``/write?db=<database>``       HTTP basic (``username`` /
                                     ``password``), omitted entirely
                                     when both are blank
v2    ``/api/v2/write?org&bucket``   ``Authorization: Token <token>``
v3    ``/api/v2/write?bucket``       ``Authorization: Bearer <token>``
===== ============================== ==============================

``v3`` covers every InfluxDB 3 product (Core, Enterprise, Cloud
Dedicated, Cloud Serverless). They all accept the v2 write endpoint;
a v3 *database* is named in the ``bucket`` parameter and ``org`` is
accepted-and-ignored by Core / Enterprise, so it is sent only when the
operator set one (Cloud Serverless does use it). Bearer is the token
scheme InfluxDB 3 documents; ``Token`` also works there, but not the
other way round, so the two are kept distinct rather than collapsed.

An operator pointing ``v1`` at an InfluxDB 3 server puts the API token
in the *password* field — that is the documented compat shim, and it
needs no code here beyond basic auth already sending it.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import httpx

from app.core.exc_text import describe_http_exc

# Line protocol timestamps are sent in whole seconds — see
# ``line_protocol.Point.timestamp``.
_PRECISION = "s"


class InfluxDBWriteError(Exception):
    """A write was rejected or could not be delivered."""


@dataclass(frozen=True)
class InfluxTargetConfig:
    """Everything the writer needs, with secrets already decrypted.

    Deliberately not the ORM row: the push path decrypts once and this
    stays a plain value object, so ``build_write_request`` is testable
    without a database.
    """

    version: str
    url: str
    database: str = ""
    username: str = ""
    password: str = ""
    org: str = ""
    bucket: str = ""
    token: str = ""
    verify_tls: bool = True
    timeout_seconds: int = 10


@dataclass(frozen=True)
class WriteRequest:
    url: str
    params: dict[str, str]
    headers: dict[str, str]
    auth: tuple[str, str] | None


def build_write_request(cfg: InfluxTargetConfig) -> WriteRequest:
    """Resolve endpoint, query params and auth for one target.

    Raises ``ValueError`` when the target is missing a field its version
    cannot write without — surfaced as a 422 on save and as the target's
    ``last_push_error`` if it is somehow reached at push time.
    """
    base = cfg.url.strip().rstrip("/")
    if not base:
        raise ValueError("url is required")

    headers: dict[str, str] = {"Content-Type": "text/plain; charset=utf-8"}
    params: dict[str, str] = {"precision": _PRECISION}
    auth: tuple[str, str] | None = None

    if cfg.version == "v1":
        if not cfg.database:
            raise ValueError("database is required for InfluxDB v1")
        url = f"{base}/write"
        params["db"] = cfg.database
        # Blank username AND blank password = an unauthenticated v1
        # server, which is a legitimate (if unusual) on-prem setup.
        if cfg.username or cfg.password:
            auth = (cfg.username, cfg.password)
    elif cfg.version in ("v2", "v3"):
        if not cfg.bucket:
            label = "database" if cfg.version == "v3" else "bucket"
            raise ValueError(f"{label} is required for InfluxDB {cfg.version}")
        if not cfg.token:
            raise ValueError(f"token is required for InfluxDB {cfg.version}")
        url = f"{base}/api/v2/write"
        params["bucket"] = cfg.bucket
        # v2 requires org; v3 ignores it on Core/Enterprise but Cloud
        # Serverless honours it, so send whatever the operator gave us.
        if cfg.org:
            params["org"] = cfg.org
        elif cfg.version == "v2":
            raise ValueError("org is required for InfluxDB v2")
        scheme = "Bearer" if cfg.version == "v3" else "Token"
        headers["Authorization"] = f"{scheme} {cfg.token}"
    else:
        raise ValueError(f"unsupported InfluxDB version {cfg.version!r}")

    return WriteRequest(url=url, params=params, headers=headers, auth=auth)


async def write_lines(cfg: InfluxTargetConfig, body: str) -> None:
    """POST one line-protocol batch. Raises ``InfluxDBWriteError``.

    A no-op for an empty body so callers don't have to special-case an
    idle tick — an empty POST is a 400 on some server versions.
    """
    if not body:
        return
    req = build_write_request(cfg)
    timeout = float(max(1, cfg.timeout_seconds))
    # ``auth`` is passed conditionally rather than as ``None``: httpx's
    # sentinel for "no auth" is ``USE_CLIENT_DEFAULT``, and ``None`` is
    # not in the parameter's declared type.
    auth_kwargs: dict[str, Any] = {"auth": req.auth} if req.auth is not None else {}
    try:
        async with httpx.AsyncClient(timeout=timeout, verify=cfg.verify_tls) as client:
            resp = await client.post(
                req.url,
                params=req.params,
                headers=req.headers,
                content=body.encode("utf-8"),
                **auth_kwargs,
            )
    # ``InvalidURL`` is deliberately named alongside ``HTTPError``: it
    # derives straight from ``Exception``, not from the httpx error base,
    # so catching ``HTTPError`` alone lets a malformed URL that passed the
    # save-time scheme check (``http://influx:80o86``) escape this
    # function entirely — aborting the whole beat sweep and rolling back
    # every *other* target's state instead of recording one failure here.
    except (httpx.HTTPError, httpx.InvalidURL) as exc:
        raise InfluxDBWriteError(describe_http_exc(exc, timeout=timeout)) from exc
    # 204 is the documented success for both endpoints; 200 shows up on
    # some proxies. Anything else carries a body worth surfacing.
    if resp.status_code not in (200, 204):
        detail = resp.text.strip()[:300]
        raise InfluxDBWriteError(f"HTTP {resp.status_code}{': ' + detail if detail else ''}")


def config_from_row(row: Any) -> InfluxTargetConfig:
    """Build a config from an ``InfluxDBTarget``, decrypting secrets.

    Decryption failures (a rotated ``SECRET_KEY``) are surfaced as
    ``InfluxDBWriteError`` rather than swallowed — pushing with an empty
    token would fail as a 401 that reads like an operator typo.
    """
    from app.core.crypto import decrypt_str

    password = ""
    token = ""
    try:
        if row.password_encrypted:
            password = decrypt_str(row.password_encrypted)
        if row.token_encrypted:
            token = decrypt_str(row.token_encrypted)
    except Exception as exc:  # noqa: BLE001 — any Fernet failure is fatal here
        raise InfluxDBWriteError(f"failed to decrypt stored credential: {exc}") from exc

    return InfluxTargetConfig(
        version=row.version,
        url=row.url,
        database=row.database or "",
        username=row.username or "",
        password=password,
        org=row.org or "",
        bucket=row.bucket or "",
        token=token,
        verify_tls=bool(row.verify_tls),
        timeout_seconds=int(row.timeout_seconds or 10),
    )


__all__ = [
    "InfluxDBWriteError",
    "InfluxTargetConfig",
    "WriteRequest",
    "build_write_request",
    "config_from_row",
    "write_lines",
]
