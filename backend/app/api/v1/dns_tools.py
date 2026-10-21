"""DNS operator tools — out-of-band utilities that don't manage state.

The first tool here is the multi-resolver propagation check: query a
record name against several public resolvers in parallel and surface
per-resolver results + RTT so an operator can see at a glance whether
a recently-edited record has propagated everywhere it should.

Lives at ``/api/v1/dns/tools/...`` and rides the existing DNS
permission gate (operators with read on dns_zone / dns_record can
fire these — they're query-only).
"""

from __future__ import annotations

import asyncio
import time

import dns.asyncresolver
import dns.exception
import dns.name
import dns.resolver
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field, field_validator

from app.api.deps import CurrentUser
from app.api.token_binding import honours_token_binding
from app.core.permissions import require_any_resource_permission
from app.services.nettools.schemas import assert_target_allowed

router = APIRouter(
    prefix="/tools",
    tags=["dns-tools"],
    dependencies=[Depends(require_any_resource_permission("dns_group", "dns_zone", "dns_record"))],
)


# Curated default resolver list. The mix balances majors (Cloudflare,
# Google, Quad9, OpenDNS) with diverse anycast networks — running all
# four protects against single-vendor cache staleness.
DEFAULT_RESOLVERS: list[dict[str, str]] = [
    {"name": "Cloudflare", "address": "1.1.1.1"},
    {"name": "Google", "address": "8.8.8.8"},
    {"name": "Quad9", "address": "9.9.9.9"},
    {"name": "OpenDNS", "address": "208.67.222.222"},
]

# Record types we expose. Keep the list short — operators bouncing through
# an ad-hoc query tool aren't asking for OPENPGPKEY.
_VALID_RECORD_TYPES: frozenset[str] = frozenset(
    {"A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA", "PTR", "SRV", "CAA", "TLSA"}
)


class PropagationCheckRequest(BaseModel):
    name: str = Field(min_length=1, max_length=253)
    record_type: str = Field(default="A")
    # Optional override — when null, falls back to the curated default list.
    resolvers: list[str] | None = Field(default=None, max_length=12)
    timeout_seconds: float = Field(default=3.0, ge=0.5, le=10.0)

    @field_validator("name")
    @classmethod
    def _validate_name(cls, v: str) -> str:
        try:
            dns.name.from_text(v)
        except dns.exception.DNSException:
            raise ValueError("Not a valid DNS name") from None
        return v.rstrip(".")

    @field_validator("resolvers")
    @classmethod
    def _validate_resolvers(cls, v: list[str] | None) -> list[str] | None:
        """Each override must be an IP literal, and one we are allowed to
        query (#923).

        Two separate reasons, and both are needed. ``Resolver.nameservers``
        accepts an address or an https URL and raises a bare ``ValueError``
        for anything else — reached from inside the ``gather``, that is an
        unhandled 500 rather than the per-resolver ``error`` status every
        other failure mode returns.

        And a resolver is a host **this server sends traffic to**, so it goes
        through the same SSRF denylist ``/tools/dns-propagation`` applies to
        its own resolver list (``nettools/schemas.py::_v_resolvers``). Without
        it, an authenticated caller could aim the control plane at loopback or
        at 169.254.169.254 and read the timing and answers back out of the
        per-resolver result — a probe of the internal network wearing the
        shape of a propagation check.
        """
        if v is None:
            return v
        return [assert_target_allowed(entry.strip()) for entry in v]

    @field_validator("record_type")
    @classmethod
    def _validate_type(cls, v: str) -> str:
        u = v.upper()
        if u not in _VALID_RECORD_TYPES:
            raise ValueError(
                f"Unsupported record type. Allowed: {', '.join(sorted(_VALID_RECORD_TYPES))}"
            )
        return u


class ResolverResult(BaseModel):
    resolver: str  # e.g. "1.1.1.1" — the IP that was queried
    name: str | None = None  # display name from the curated list, if known
    status: str  # "ok" | "nxdomain" | "timeout" | "error"
    rtt_ms: float | None = None
    answers: list[str] = []  # rendered RDATA strings
    error: str | None = None


class PropagationCheckResult(BaseModel):
    name: str
    record_type: str
    queried_at_ms: int
    results: list[ResolverResult]


async def _query_one(
    resolver_ip: str,
    display_name: str | None,
    qname: str,
    qtype: str,
    timeout: float,
) -> ResolverResult:
    """Fire a single A/AAAA/whatever query against ``resolver_ip``.

    Uses a fresh dnspython AsyncResolver per call so each lookup carries
    its own state and timeout — a slow resolver can't poison the others.
    """
    rt = dns.asyncresolver.Resolver(configure=False)
    rt.nameservers = [resolver_ip]
    rt.timeout = timeout
    rt.lifetime = timeout

    started = time.perf_counter()
    try:
        answer = await rt.resolve(qname, qtype, raise_on_no_answer=False)
        rtt_ms = (time.perf_counter() - started) * 1000.0
        rendered = [str(rr) for rr in answer] if answer.rrset else []
        if not rendered:
            return ResolverResult(
                resolver=resolver_ip,
                name=display_name,
                status="nxdomain",
                rtt_ms=rtt_ms,
                answers=[],
            )
        return ResolverResult(
            resolver=resolver_ip,
            name=display_name,
            status="ok",
            rtt_ms=rtt_ms,
            answers=rendered,
        )
    except dns.resolver.NXDOMAIN:
        rtt_ms = (time.perf_counter() - started) * 1000.0
        return ResolverResult(
            resolver=resolver_ip,
            name=display_name,
            status="nxdomain",
            rtt_ms=rtt_ms,
        )
    except dns.exception.Timeout:
        return ResolverResult(
            resolver=resolver_ip,
            name=display_name,
            status="timeout",
            rtt_ms=None,
            error=f"timeout after {timeout:.1f}s",
        )
    except dns.exception.DNSException as e:
        rtt_ms = (time.perf_counter() - started) * 1000.0
        return ResolverResult(
            resolver=resolver_ip,
            name=display_name,
            status="error",
            rtt_ms=rtt_ms,
            error=str(e) or e.__class__.__name__,
        )
    except OSError as e:
        # Network error — resolver unreachable, no route, etc.
        return ResolverResult(
            resolver=resolver_ip,
            name=display_name,
            status="error",
            rtt_ms=None,
            error=f"network error: {e}",
        )


@router.post("/propagation-check", response_model=PropagationCheckResult)
@honours_token_binding
async def propagation_check(
    body: PropagationCheckRequest, current_user: CurrentUser
) -> PropagationCheckResult:
    """Query the same record across several public resolvers.

    Surfaces propagation drift after a record edit — Cloudflare and
    Google often serve different versions during the TTL window after
    a change. Returns per-resolver status (ok / nxdomain / timeout /
    error), RTT, and the answer RDATA. All queries fire in parallel.
    """
    # Resolve which resolver list to query. When the operator passes an
    # explicit list, we honour it; otherwise default to the curated set.
    targets: list[tuple[str, str | None]]
    if body.resolvers:
        targets = [(ip, None) for ip in body.resolvers]
    else:
        targets = [(r["address"], r["name"]) for r in DEFAULT_RESOLVERS]

    if not targets:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="At least one resolver is required",
        )

    results = await asyncio.gather(
        *[
            _query_one(ip, name, body.name, body.record_type, body.timeout_seconds)
            for ip, name in targets
        ]
    )
    return PropagationCheckResult(
        name=body.name,
        record_type=body.record_type,
        queried_at_ms=int(time.time() * 1000),
        results=list(results),
    )


@router.get("/default-resolvers", response_model=list[dict[str, str]])
@honours_token_binding
async def list_default_resolvers(
    current_user: CurrentUser,
) -> list[dict[str, str]]:
    """Return the curated public-resolver list used by ``propagation-check``.

    Frontend uses this to render the "querying X" badges before the
    request returns, so the user sees what's about to happen.
    """
    return DEFAULT_RESOLVERS
