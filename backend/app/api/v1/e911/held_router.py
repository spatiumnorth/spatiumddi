"""The HELD endpoint — RFC 5985 (#972 Phase 1b).

``POST /held`` with ``application/held+xml``, returning PIDF-LO. Mounted at
the application root rather than under ``/api/v1`` because a HELD client is
configured with a whole URL and the protocol names this path; the ACME
``.well-known`` route is mounted the same way for the same reason.

**Authenticated like any other API surface.** A third-party caller — a
PBX, Cisco Emergency Responder, RedSky — uses an API token scoped to
``/held`` with the ``e911_location`` read permission. The unauthenticated
device-self-query mode RFC 5985 §6 describes is Phase 2 and is off by
default (see ``E911_SELF_QUERY_ENABLED``), because an unauthenticated
endpoint that answers "where is the device at this IP" is one an attacker
inside the network can walk.

**A request with no identity is REFUSED while self-query is off.** That is
the load-bearing refusal on this surface: RFC 5985's default is to answer
from the requester's own address, so falling through would hand a PBX the
location of *its own server* in response to a question about a phone —
a perfectly-formed answer that is completely wrong, which is worse than an
error. The Phase 2 self-query path is opt-in precisely so that behaviour
is never reached by accident.

Every answer writes an ``e911_resolution_log`` row, exactly as the JSON
lookup does. The protocol is different; the fact that somebody asked where
a person sits is not.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import DB, CurrentUser
from app.api.v1.e911.router import log_resolution
from app.config import settings
from app.core.auth_throttle import e911_self_query_rate_limited
from app.core.body_limit import read_body_capped
from app.core.mac import canonicalize_mac
from app.core.permissions import require_resource_permission
from app.core.responses import HeldXmlResponse
from app.models.auth import User
from app.services.e911.held import (
    ERROR_CANNOT_PROVIDE,
    ERROR_LOCATION_UNKNOWN,
    ERROR_NOT_LOCATABLE,
    ERROR_REQUEST_ERROR,
    MAX_REQUEST_BYTES,
    HeldError,
    HeldRequest,
    parse_location_request,
    render_error,
    render_location_response,
)
from app.services.e911.pidf_lo import render_pidf_lo
from app.services.e911.resolver import resolve_location

router = APIRouter(tags=["e911"])

HELD_MEDIA_TYPE = "application/held+xml"


async def _read_document(request: Request) -> bytes:
    """The request body, read no further than ``MAX_REQUEST_BYTES``.

    The self-query route has no login to check first (it is unauthenticated
    by design, and off unless ``E911_SELF_QUERY_ENABLED``), so the size is
    the only bound on what an unauthenticated sender can make the api read.
    ``parse_location_request`` refuses an oversized document too, but only
    after reading it whole. A body over the limit gets the same HELD error,
    without reading past the limit (#2780)."""
    try:
        return await read_body_capped(request, MAX_REQUEST_BYTES)
    except HTTPException as exc:
        if exc.status_code != status.HTTP_413_CONTENT_TOO_LARGE:
            raise
        raise HeldError(
            ERROR_REQUEST_ERROR, f"request larger than {MAX_REQUEST_BYTES} bytes"
        ) from exc


def _error(code: str, message: str, http_status: int) -> Response:
    return Response(
        content=render_error(code, message),
        media_type=HELD_MEDIA_TYPE,
        status_code=http_status,
    )


async def _answer(
    db: AsyncSession,
    request: Request,
    held: HeldRequest,
    *,
    user: User | None,
    api_token_id: uuid.UUID | None,
    actor_kind: str,
) -> Response:
    """Shared body for both HELD modes.

    The only difference between the authenticated and the self-query path is
    where the identity comes from and who is recorded as the actor — so they
    share this, rather than growing a second copy of the resolve-log-render
    sequence that could drift. The request is parsed by the caller and
    passed in, so the body is parsed once.
    """
    mac = held.mac
    if mac:
        try:
            mac = canonicalize_mac(mac)
        except ValueError as exc:
            return _error(ERROR_REQUEST_ERROR, str(exc), status.HTTP_400_BAD_REQUEST)

    resolution = await resolve_location(
        db,
        ip=held.ip,
        mac=mac,
        chassis_id=held.chassis_id,
        port_id=held.port_id,
    )

    source_ip = request.client.host if request.client else None
    log_resolution(
        db,
        resolution,
        user_id=user.id if user else None,
        api_token_id=api_token_id,
        source_ip=source_ip,
        actor_kind=actor_kind,
    )
    await db.commit()

    if resolution.erl is None:
        # 404 with locationUnknown, which is what RFC 5985 §6.3 says and what
        # a provider's retry logic expects. An empty 200 would read as "this
        # device has no location by design".
        return _error(
            ERROR_LOCATION_UNKNOWN,
            resolution.degraded_reason or "no dispatchable location for that identity",
            status.HTTP_404_NOT_FOUND,
        )

    # RFC 5985 §6.1: with exact="true" the client wants ONLY the types it
    # listed. Honoured rather than parsed-and-ignored, which is what the first
    # version did — a caller asking exactly for `geodetic` against an ERL with
    # no coordinates got a 200 carrying civic data it had explicitly said it
    # could not use, and would render nothing from.
    if held.exact and not held.wants_civic:
        has_point = resolution.erl.latitude is not None and resolution.erl.longitude is not None
        if not has_point:
            return _error(
                ERROR_CANNOT_PROVIDE,
                "this location has no coordinates; only a civic address is "
                "available and the request asked exactly for geodetic",
                status.HTTP_400_BAD_REQUEST,
            )

    pidf = render_pidf_lo(
        resolution.erl,
        entity=f"pres:{resolution.identity_kind}:{resolution.identity_value}",
        rule_matched=resolution.rule_matched,
        observed_at=resolution.observed_at,
    )
    return Response(
        content=render_location_response(pidf),
        media_type=HELD_MEDIA_TYPE,
        # The resolver's verdict, on the wire, for a client that logs
        # headers: PIDF-LO has nowhere to say "this is a fallback answer",
        # and dropping the distinction entirely would undo the whole point
        # of the freshness rule.
        headers={
            "X-SpatiumDDI-Confidence": resolution.confidence,
            "X-SpatiumDDI-Rule": resolution.rule_matched or "none",
        },
    )


@router.post(
    "/held",
    response_class=HeldXmlResponse,
    dependencies=[Depends(require_resource_permission("e911_location"))],
    summary="HELD locationRequest (RFC 5985) — returns PIDF-LO",
)
async def held_third_party(request: Request, db: DB, user: CurrentUser) -> Response:
    """Third-party HELD: the caller names the device (RFC 6155 identity)."""
    try:
        held = parse_location_request(await _read_document(request))
    except HeldError as exc:
        return _error(exc.code, exc.message, status.HTTP_400_BAD_REQUEST)

    if not held.has_identity:
        return _error(
            ERROR_NOT_LOCATABLE,
            "name the device with an ip, mac, or chassis+port identity. "
            "This endpoint does not answer from the requester's own address; "
            "that is the opt-in device self-query mode.",
            status.HTTP_400_BAD_REQUEST,
        )

    return await _answer(
        db,
        request,
        held,
        user=user,
        api_token_id=getattr(request.state, "api_token_id", None),
        actor_kind="api_token" if getattr(request.state, "api_token_id", None) else "user",
    )


@router.post(
    "/held/self",
    response_class=HeldXmlResponse,
    summary="HELD self-query — a device asks about itself (opt-in, unauthenticated)",
)
async def held_self_query(request: Request, db: DB) -> Response:
    """RFC 5985 §6: the LIS answers a device's own request by source address.

    Four properties, each of which exists because this endpoint has no
    authentication at all:

    * **Off unless ``E911_SELF_QUERY_ENABLED``.** A 404 rather than a 403
      when disabled, so the surface does not advertise itself to a scanner.
    * **Identity is the TCP source address, ALWAYS.** A body-supplied
      ``<ip>`` is ignored on this path — honouring it would turn an
      unauthenticated endpoint into a location oracle for the whole estate,
      which is precisely the attack the authenticated variant's token
      prevents.
    * **Rate-limited fail-closed** per source IP. A phone asks at boot and
      on a link change, not in a loop.
    * **The response carries the location and nothing else.** That falls out
      of PIDF-LO carrying only an address, and the header hints the
      authenticated path sets are omitted here: `confidence` and the rule
      name describe our INTERNAL evidence, and a device has no need to learn
      that it was located by switch port.
    """
    if not settings.e911_self_query_enabled:
        return _error(
            ERROR_REQUEST_ERROR,
            "device self-query is not enabled on this server",
            status.HTTP_404_NOT_FOUND,
        )

    source_ip = request.client.host if request.client else None
    if source_ip is None:
        # Checked BEFORE the throttle. The throttle refuses a falsy address
        # (it fails closed), so asking it first answered 429 — "slow down" —
        # for a request that can never succeed no matter how slowly it is
        # retried, and made this accurate message unreachable. There is no safe
        # fallback here: answering from a body-supplied address is the oracle
        # this endpoint exists to avoid being.
        return _error(
            ERROR_NOT_LOCATABLE,
            "could not determine the requesting address",
            status.HTTP_400_BAD_REQUEST,
        )

    if await e911_self_query_rate_limited(source_ip):
        return _error(
            ERROR_REQUEST_ERROR,
            "too many location requests from this address",
            status.HTTP_429_TOO_MANY_REQUESTS,
        )

    try:
        parsed = parse_location_request(await _read_document(request))
    except HeldError as exc:
        return _error(exc.code, exc.message, status.HTTP_400_BAD_REQUEST)

    # Rebuilt from the source address alone. Every identity the body carried
    # is discarded, including an <ip> that happens to match — accepting it
    # when it matches and rejecting it when it does not would leak, by
    # timing, whether a guessed address is the caller's.
    self_request = HeldRequest(
        location_types=parsed.location_types,
        exact=parsed.exact,
        ip=source_ip,
    )
    return await _answer(
        db,
        request,
        self_request,
        user=None,
        api_token_id=None,
        actor_kind="device_self",
    )
