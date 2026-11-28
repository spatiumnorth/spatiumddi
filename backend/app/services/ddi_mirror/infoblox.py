"""Infoblox NIOS WAPI provider for the commercial-DDI mirror (#4729).

Read-only: only ``GET`` is ever issued. Authentication is HTTP basic. Listing
uses WAPI paging (``_paging=1``, ``_return_as_object=1``, ``_max_results`` and
the ``next_page_id`` chain) so a large grid is never pulled in one response,
with a hard per-kind object cap, a request timeout, one request at a time and a
short pause between pages. A ``429`` is honoured via ``Retry-After`` (bounded).

IPv4 only for now: ``ipv6network`` / ``ipv6range`` / ``record:aaaa`` and the
other record types (CNAME, MX, TXT, SRV, ...) are not mirrored, and
``record:host`` rows are mirrored as-is (their IPv6 addresses are not).

Parsing is defensive — WAPI response shapes vary by version and the tests run
on recorded fixture JSON, so every accessor guards missing keys.
"""

from __future__ import annotations

import asyncio
import ipaddress
import ssl
from dataclasses import dataclass
from typing import Any

import httpx
import structlog

from app.core.exc_text import describe_exc
from app.services.ddi_mirror.base import (
    KIND_A,
    KIND_CONTAINER,
    KIND_HOST,
    KIND_NETWORK,
    KIND_PTR,
    KIND_RANGE,
    KIND_RESERVATION,
    KIND_VIEW,
    KIND_ZONE,
    DDIProvider,
    DDIProviderError,
    FetchResult,
    ProbeInfo,
    ProviderConfig,
    SourceObject,
)

logger = structlog.get_logger(__name__)

# Hard ceiling on objects pulled per kind per run. Past it the kind is reported
# incomplete and nothing is deleted from the mirror on its account.
MAX_OBJECTS_PER_KIND = 500_000
_REQUEST_TIMEOUT = httpx.Timeout(30.0, connect=10.0)
_PAGE_PAUSE_SECONDS = 0.05
_MAX_RETRIES = 3
_MAX_RETRY_AFTER = 30.0


@dataclass(frozen=True)
class _Spec:
    wapi_object: str
    fields: str
    # WAPI query parameter the configured view filter maps to, if any.
    view_param: str | None = None  # "network_view" | "view"


_SPECS: dict[str, _Spec] = {
    KIND_VIEW: _Spec("view", "name,comment,is_default"),
    KIND_CONTAINER: _Spec(
        "networkcontainer", "network,network_view,comment,extattrs", "network_view"
    ),
    KIND_NETWORK: _Spec(
        "network", "network,network_view,comment,extattrs,disable,options", "network_view"
    ),
    KIND_RANGE: _Spec(
        "range",
        "start_addr,end_addr,network,network_view,comment,name,disable,server_association_type",
        "network_view",
    ),
    KIND_RESERVATION: _Spec(
        "fixedaddress",
        "ipv4addr,mac,name,network,network_view,comment,disable,match_client",
        "network_view",
    ),
    KIND_ZONE: _Spec("zone_auth", "fqdn,view,comment,zone_format,disable", "view"),
    KIND_HOST: _Spec("record:host", "name,ipv4addrs,view,zone,comment,ttl,extattrs", "view"),
    KIND_A: _Spec("record:a", "name,ipv4addr,view,zone,comment,ttl,disable", "view"),
    KIND_PTR: _Spec("record:ptr", "name,ptrdname,ipv4addr,view,zone,comment,ttl", "view"),
}


def _s(value: Any) -> str:
    return "" if value is None else str(value).strip()


def _extattrs(raw: Any) -> dict[str, Any]:
    """``{"Site": {"value": "HQ"}}`` -> ``{"Site": "HQ"}``."""
    out: dict[str, Any] = {}
    if isinstance(raw, dict):
        for k, v in raw.items():
            out[str(k)] = v.get("value") if isinstance(v, dict) else v
    return out


def _cidr(value: Any) -> str | None:
    try:
        return str(ipaddress.ip_network(_s(value), strict=False))
    except ValueError:
        return None


def _ipv4(value: Any) -> str | None:
    try:
        return str(ipaddress.IPv4Address(_s(value)))
    except ValueError:
        return None


def _map(kind: str, raw: dict[str, Any]) -> SourceObject | str:
    """Map one WAPI object, or return the reason it cannot be mapped."""
    ref = _s(raw.get("_ref"))
    if not ref:
        return "object without a _ref"
    comment = _s(raw.get("comment"))

    if kind == KIND_VIEW:
        name = _s(raw.get("name"))
        if not name:
            return f"{ref}: view without a name"
        return SourceObject(
            kind, ref, name=name, comment=comment, data={"is_default": bool(raw.get("is_default"))}
        )

    if kind in (KIND_CONTAINER, KIND_NETWORK):
        cidr = _cidr(raw.get("network"))
        if cidr is None:
            return f"{ref}: unparseable network {raw.get('network')!r}"
        data: dict[str, Any] = {"extattrs": _extattrs(raw.get("extattrs"))}
        if kind == KIND_NETWORK:
            data["disabled"] = bool(raw.get("disable"))
            options = raw.get("options")
            if isinstance(options, list):
                data["options"] = {
                    _s(o.get("name")): _s(o.get("value"))
                    for o in options
                    if isinstance(o, dict) and o.get("name")
                }
        return SourceObject(
            kind,
            ref,
            name=cidr,
            view=_s(raw.get("network_view")),
            value=cidr,
            comment=comment,
            data=data,
        )

    if kind == KIND_RANGE:
        start, end = _ipv4(raw.get("start_addr")), _ipv4(raw.get("end_addr"))
        if start is None or end is None:
            return f"{ref}: unparseable range {raw.get('start_addr')!r}-{raw.get('end_addr')!r}"
        value = f"{start}-{end}"
        return SourceObject(
            kind,
            ref,
            name=_s(raw.get("name")) or value,
            view=_s(raw.get("network_view")),
            value=value,
            comment=comment,
            data={
                "network": _cidr(raw.get("network")) or "",
                "start": start,
                "end": end,
                "disabled": bool(raw.get("disable")),
                "server_association_type": _s(raw.get("server_association_type")),
            },
        )

    if kind == KIND_RESERVATION:
        ip = _ipv4(raw.get("ipv4addr"))
        if ip is None:
            return f"{ref}: unparseable fixed address {raw.get('ipv4addr')!r}"
        return SourceObject(
            kind,
            ref,
            name=_s(raw.get("name")),
            view=_s(raw.get("network_view")),
            value=ip,
            comment=comment,
            data={
                "mac": _s(raw.get("mac")).lower(),
                "network": _cidr(raw.get("network")) or "",
                "disabled": bool(raw.get("disable")),
                "match_client": _s(raw.get("match_client")),
            },
        )

    if kind == KIND_ZONE:
        fqdn = _s(raw.get("fqdn")).rstrip(".").lower()
        if not fqdn:
            return f"{ref}: zone without an fqdn"
        return SourceObject(
            kind,
            ref,
            name=fqdn,
            view=_s(raw.get("view")),
            value=fqdn,
            comment=comment,
            data={
                "zone_format": _s(raw.get("zone_format")),
                "disabled": bool(raw.get("disable")),
            },
        )

    # ── DNS records ───────────────────────────────────────────────
    name = _s(raw.get("name")).rstrip(".").lower()
    if not name:
        return f"{ref}: record without a name"
    base = {
        "zone": _s(raw.get("zone")).rstrip(".").lower(),
        "ttl": raw.get("ttl"),
        "disabled": bool(raw.get("disable")),
    }
    view = _s(raw.get("view"))

    if kind == KIND_HOST:
        addrs: list[dict[str, Any]] = []
        for a in raw.get("ipv4addrs") or []:
            ip = _ipv4(a.get("ipv4addr")) if isinstance(a, dict) else None
            if ip:
                addrs.append(
                    {
                        "ip": ip,
                        "mac": _s(a.get("mac")).lower(),
                        "dhcp": bool(a.get("configure_for_dhcp")),
                    }
                )
        if not addrs:
            return f"{ref}: host record {name} has no IPv4 address"
        return SourceObject(
            kind,
            ref,
            name=name,
            view=view,
            value=",".join(a["ip"] for a in addrs),
            comment=comment,
            data={**base, "addresses": addrs, "extattrs": _extattrs(raw.get("extattrs"))},
        )

    if kind == KIND_A:
        ip = _ipv4(raw.get("ipv4addr"))
        if ip is None:
            return f"{ref}: A record {name} has no IPv4 address"
        return SourceObject(kind, ref, name=name, view=view, value=ip, comment=comment, data=base)

    if kind == KIND_PTR:
        target = _s(raw.get("ptrdname")).rstrip(".").lower()
        if not target:
            return f"{ref}: PTR record {name} has no target"
        return SourceObject(
            kind,
            ref,
            name=name,
            view=view,
            value=target,
            comment=comment,
            data={**base, "ip": _ipv4(raw.get("ipv4addr")) or ""},
        )

    return f"{ref}: unsupported kind {kind}"


class InfobloxProvider(DDIProvider):
    vendor = "infoblox"
    label = "Infoblox NIOS (WAPI)"
    kinds = tuple(_SPECS)

    def __init__(self, config: ProviderConfig) -> None:
        super().__init__(config)
        self._client: httpx.AsyncClient | None = None

    # ── Lifecycle ────────────────────────────────────────────────────

    @staticmethod
    def _verify(cfg: ProviderConfig) -> Any:
        if not cfg.verify_tls:
            logger.warning("ddi_mirror_tls_verification_disabled", endpoint=cfg.base_url)
            return False
        ca = (cfg.ca_bundle_pem or "").strip()
        if ca:
            return ssl.create_default_context(cadata=ca)
        return True

    async def __aenter__(self) -> InfobloxProvider:
        cfg = self.config
        version = cfg.api_version.strip().lstrip("/") or "v2.12"
        self._client = httpx.AsyncClient(
            base_url=f"{cfg.base_url.rstrip('/')}/wapi/{version}/",
            auth=httpx.BasicAuth(cfg.username, cfg.password),
            headers={"Accept": "application/json"},
            verify=self._verify(cfg),
            timeout=_REQUEST_TIMEOUT,
            transport=cfg.transport,
            follow_redirects=False,
        )
        return self

    async def __aexit__(self, *exc: Any) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    # ── HTTP ─────────────────────────────────────────────────────────

    async def _get(self, path: str, params: dict[str, Any]) -> Any:
        assert self._client is not None, "use as an async context manager"
        for attempt in range(_MAX_RETRIES + 1):
            try:
                # "./" keeps httpx from reading "record:host" as a URL scheme.
                resp = await self._client.get(f"./{path}", params=params)
            except httpx.HTTPError as exc:
                raise DDIProviderError(f"Infoblox request failed: {describe_exc(exc)}") from exc
            if resp.status_code == 429 and attempt < _MAX_RETRIES:
                try:
                    wait = float(resp.headers.get("Retry-After", "1"))
                except ValueError:
                    wait = 1.0
                await asyncio.sleep(min(max(wait, 0.0), _MAX_RETRY_AFTER))
                continue
            break
        if resp.status_code >= 400:
            raise DDIProviderError(
                f"Infoblox WAPI {path.rstrip('/')} returned HTTP {resp.status_code}: "
                f"{self._error_text(resp)}",
                status_code=resp.status_code,
            )
        try:
            return resp.json()
        except ValueError as exc:
            raise DDIProviderError(
                "Infoblox WAPI returned a non-JSON response — is the URL the grid master?",
                status_code=resp.status_code,
            ) from exc

    @staticmethod
    def _error_text(resp: httpx.Response) -> str:
        try:
            body = resp.json()
        except ValueError:
            return (resp.text or "")[:200]
        if isinstance(body, dict):
            return str(body.get("text") or body.get("Error") or body)[:200]
        return str(body)[:200]

    # ── Provider API ─────────────────────────────────────────────────

    async def probe(self) -> ProbeInfo:
        body = await self._get("grid", {"_max_results": 1, "_return_fields": "name"})
        if not isinstance(body, list):
            raise DDIProviderError("Unexpected response from the WAPI grid object")
        name = _s(body[0].get("name")) if body and isinstance(body[0], dict) else ""
        return ProbeInfo(
            version=f"WAPI {self.config.api_version}",
            detail=f"grid {name}" if name else "",
        )

    async def fetch(self, kind: str) -> FetchResult:
        spec = _SPECS.get(kind)
        if spec is None:
            raise DDIProviderError(f"Infoblox provider does not mirror {kind!r}")
        cfg = self.config
        params: dict[str, Any] = {
            "_return_fields": spec.fields,
            "_paging": 1,
            "_return_as_object": 1,
            "_max_results": max(1, int(cfg.page_size)),
        }
        view_filter = {"network_view": cfg.network_view, "view": cfg.dns_view}.get(
            spec.view_param or ""
        )
        if spec.view_param and view_filter:
            params[spec.view_param] = view_filter
        if kind == KIND_VIEW and cfg.dns_view:
            params["name"] = cfg.dns_view

        result = FetchResult()
        seen: set[str] = set()
        page_id: str | None = None
        while True:
            page_params = dict(params)
            if page_id:
                page_params["_page_id"] = page_id
            body = await self._get(spec.wapi_object, page_params)
            if not isinstance(body, dict) or not isinstance(body.get("result"), list):
                raise DDIProviderError(
                    f"Unexpected paged response for {spec.wapi_object} (no 'result' list)"
                )
            for raw in body["result"]:
                if not isinstance(raw, dict):
                    result.unmapped.append("non-object entry in result list")
                    continue
                mapped = _map(kind, raw)
                if isinstance(mapped, str):
                    result.unmapped.append(mapped)
                elif mapped.source_ref not in seen:
                    seen.add(mapped.source_ref)
                    result.objects.append(mapped)
            page_id = body.get("next_page_id") or None
            if not page_id:
                break
            if len(result.objects) >= MAX_OBJECTS_PER_KIND:
                result.complete = False
                break
            await asyncio.sleep(_PAGE_PAUSE_SECONDS)
        return result


__all__ = ["MAX_OBJECTS_PER_KIND", "InfobloxProvider"]
