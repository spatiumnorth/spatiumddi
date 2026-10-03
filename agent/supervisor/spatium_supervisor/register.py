"""Supervisor → control-plane register flow (#170 Wave A2).

Calls ``POST /api/v1/appliance/supervisor/register`` with the
supervisor's identity material + a pairing code, and persists the
returned ``appliance_id`` so subsequent boots can skip re-registration.

Failure modes:

* Feature flag disabled on the control plane (404) → log + retry on
  next supervisor restart; the operator may not have flipped the
  flag yet.
* Pairing code invalid / expired / claimed (403) → fatal. Clear the
  cached pairing code from env so we don't crash-loop on a dead
  code. Wave A2's behaviour is "log loud + idle"; Wave B+'s console
  dashboard will surface a recover-from-failed-pair affordance.
* Attempt budget spent (429, #1356) → stop this round and let the main
  loop try again on its next tick. Retrying every couple of seconds
  cannot succeed before the window passes, and each retry is another
  request against an endpoint that is refusing them.
* Network unreachable / 5xx → backoff + retry forever (a 503 with a
  ``Retry-After`` is honoured, capped). The supervisor
  is the only path to bring the appliance into the fleet; if the
  control plane is briefly down the supervisor should keep trying
  rather than fall over.
"""

from __future__ import annotations

import base64
import time
from dataclasses import dataclass

import httpx
import structlog

from .identity import Identity

log = structlog.get_logger()


@dataclass(frozen=True)
class RegisterResult:
    appliance_id: str
    state: str
    public_key_fingerprint: str
    # Cleartext session token returned by B1's register endpoint.
    # Re-presented on every /supervisor/poll + /supervisor/heartbeat
    # call until approval lands the mTLS switch (Wave C2/D). Stored
    # on disk under ``{state_dir}/identity/session_token`` so a
    # supervisor restart between register + approve still authenticates.
    session_token: str


class RegisterFatal(Exception):
    """Pairing code is dead. The supervisor should clear it from
    config + stop trying until an operator pastes a new one."""


class RegisterCodeRejected(RegisterFatal):
    """Control plane returned 403 — this pairing code will never work
    (invalid / expired / revoked / used up). The caller drops it rather
    than re-presenting it every loop tick: each retry spends one of the
    address's registration attempts (#1356), so a box stuck on a dead code
    would keep its address throttled and lock out every other appliance
    pairing from behind the same NAT."""


class RegisterDisabled(Exception):
    """Control plane returned 404 — feature flag is off. Retry on
    next boot; in the meantime the supervisor falls back to idle."""


class RegisterThrottled(Exception):
    """Control plane returned 429 — too many failed registration attempts
    from this address (or install-wide) in the current window (#1356). The
    caller retries on its next loop tick instead of in a tight loop."""


# Longest a 503's Retry-After may pause one attempt. The control plane asks
# for 60 s while its attempt limiter is unreachable; the cap keeps a large or
# hostile value from parking the supervisor's startup.
_MAX_RETRY_AFTER_S = 30.0


def _retry_after_seconds(resp: httpx.Response) -> float:
    try:
        return max(0.0, float(resp.headers.get("Retry-After", "")))
    except ValueError:
        return 0.0


def register(
    *,
    control_plane_url: str,
    pairing_code: str,
    identity: Identity,
    hostname: str,
    supervisor_version: str,
    client: httpx.Client,
    appliance_variant: str | None = None,
    max_attempts: int = 60,
    backoff_seconds: float = 2.0,
) -> RegisterResult:
    """Block until the supervisor successfully registers OR a fatal
    error happens. Each retry is constant ``backoff_seconds`` rather
    than exponential — the supervisor's whole job until registered is
    to retry registration, so polling cadence > retry-pause cadence.
    """
    payload: dict[str, object] = {
        "pairing_code": pairing_code,
        "hostname": hostname,
        "public_key_der_b64": base64.b64encode(identity.public_key_der).decode("ascii"),
        "supervisor_version": supervisor_version,
    }
    if appliance_variant is not None:
        # #272 Phase 1 — control plane stamps Appliance.appliance_variant
        # + auto-assigns the variant's fixed role set at register time
        # instead of waiting for the first heartbeat.
        payload["appliance_variant"] = appliance_variant
    url = control_plane_url.rstrip("/") + "/api/v1/appliance/supervisor/register"

    last_error: str | None = None
    for attempt in range(1, max_attempts + 1):
        try:
            resp = client.post(url, json=payload, timeout=10.0)
        except httpx.HTTPError as exc:
            last_error = f"network: {exc}"
            log.warning(
                "supervisor.register.network_error",
                attempt=attempt,
                error=str(exc),
            )
            time.sleep(backoff_seconds)
            continue

        if resp.status_code == 200:
            body = resp.json()
            log.info(
                "supervisor.register.ok",
                appliance_id=body["appliance_id"],
                state=body["state"],
                fingerprint=body.get("public_key_fingerprint"),
            )
            return RegisterResult(
                appliance_id=body["appliance_id"],
                state=body["state"],
                public_key_fingerprint=body["public_key_fingerprint"],
                session_token=body["session_token"],
            )
        if resp.status_code == 404:
            # Feature flag disabled on the control plane — wait for
            # the operator to flip it. Caller idles + retries on
            # next boot.
            raise RegisterDisabled(
                "Control plane has supervisor_registration_enabled=false; "
                "operator must enable it in platform settings."
            )
        if resp.status_code == 422:
            # Malformed request — pubkey rejected, or shape changed
            # between supervisor + control-plane versions. Fatal —
            # retrying won't fix it.
            raise RegisterFatal(
                f"control plane rejected our register payload as malformed: {resp.text}"
            )
        if resp.status_code == 403:
            raise RegisterCodeRejected(
                "Pairing code rejected by control plane "
                "(invalid / expired / already used). "
                "Generate a fresh pairing code in the Pairing tab."
            )
        if resp.status_code == 429:
            raise RegisterThrottled(
                "Control plane is refusing registration attempts from this "
                f"address for now (Retry-After: {resp.headers.get('Retry-After', '?')} s)."
            )

        # 5xx — retry.
        last_error = f"http {resp.status_code}: {resp.text}"
        log.warning(
            "supervisor.register.server_error",
            attempt=attempt,
            status=resp.status_code,
            body=resp.text[:200],
        )
        time.sleep(
            max(backoff_seconds, min(_retry_after_seconds(resp), _MAX_RETRY_AFTER_S))
        )

    raise RegisterFatal(
        f"register failed after {max_attempts} attempts; last error: {last_error}"
    )
