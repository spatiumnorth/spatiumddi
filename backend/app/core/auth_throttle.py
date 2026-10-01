"""Redis-backed throttles for the auth surface.

Two complements to the per-account lockout (#71):

* ``login_rate_limited`` — a per-source-IP attempt budget on
  ``/auth/login`` + ``/auth/login/mfa`` (#4). Account lockout needs a
  *valid username* to engage, so an attacker spraying usernames gets one
  free guess each before lockout triggers; an IP budget caps that.
* ``mfa_challenge_consume`` — single-use consumption of an MFA challenge
  ``jti`` so a captured (challenge + TOTP) pair can't be replayed inside
  the 5-minute token TTL (#7).

* ``stepup_password_blocked`` / ``record_stepup_password_failure`` — a
  per-ACCOUNT budget on wrong answers to an in-session step-up (MFA
  enrolment, disable, recovery-code regeneration; #1241). Those checks run
  for a caller who already holds a session, which is exactly the hijacked
  session they exist to stop — unthrottled, each one is a password oracle.
  Keyed by account, not IP: the session is the attacker's, the address is
  whatever they like.

Plus one that is not an auth throttle at all:

* ``e911_self_query_rate_limited`` — a per-source-IP budget on the
  unauthenticated HELD device self-query (#972).

**The login throttles fail OPEN** when Redis is unreachable: the
per-account lockout + the always-required second factor remain the hard
backstops, so a Redis outage degrades them to no-ops rather than locking
everyone out.

**The step-up throttle fails CLOSED** (``StepupThrottleUnavailable``). The
account lockout counts wrong SIGN-IN answers, not step-up answers, so for a
hijacked session nothing else bounds the guessing: failing open would give
it unlimited password guesses for as long as Redis is down, which on a
Compose install (health-checked on ``/health/live``) is the whole outage.
Refusing costs little — enrolling, disabling or regenerating MFA waits for
Redis, while sign-in and everything else keeps working. Measured on the
ddi-pg gate walk of #1241: with Redis stopped, eight wrong answers in a row
each got 403 and none got 429.

**The E911 one fails CLOSED**, and that inversion is the point rather than
an oversight — see its docstring. It is not a complement to another
protection; behind it sits an endpoint with no authentication at all.
"""

from __future__ import annotations

import structlog

from app.config import settings
from app.core.redis_client import make_async_redis

logger = structlog.get_logger(__name__)

# 30 attempts / 60 s / IP. Generous enough that a NAT'd office or a
# password-manager retry storm won't trip it, tight enough to throttle
# scripted username spraying.
_LOGIN_RL_MAX = 30
_LOGIN_RL_WINDOW_SECONDS = 60

# Matches create_mfa_challenge_token's _MFA_TOKEN_TTL_MINUTES (5 min) —
# once the challenge JWT expires the used-marker is moot.
_MFA_USED_TTL_SECONDS = 5 * 60

# 5 wrong step-up answers / 15 min / account (#1241). A person mistyping
# gets several goes; a script guessing a password from a stolen session
# gets five an hour-quarter.
_STEPUP_FAIL_MAX = 5
_STEPUP_FAIL_WINDOW_SECONDS = 15 * 60

# 10 self-queries / 5 min / IP (#972 Phase 2). A phone asks for its own
# location at boot and on a link change, not in a loop — so this is loose
# for the legitimate caller and tight for anything enumerating a VLAN.
_E911_SELF_RL_MAX = 10
_E911_SELF_RL_WINDOW_SECONDS = 300


async def login_rate_limited(ip: str | None) -> bool:
    """Increment the per-IP login counter and return True once it exceeds
    the window budget. Fails open (False) when ``ip`` is unknown or Redis
    is unavailable."""
    if not ip:
        return False
    key = f"login_rl:{ip}"
    try:
        r = make_async_redis(settings.redis_url, socket_connect_timeout=2)
        try:
            count = await r.incr(key)
            if count == 1:
                await r.expire(key, _LOGIN_RL_WINDOW_SECONDS)
            return int(count) > _LOGIN_RL_MAX
        finally:
            await r.aclose()
    except Exception as exc:  # noqa: BLE001 — throttle must never break login
        logger.warning("login_rate_limit_redis_unavailable", error=str(exc))
        return False


async def e911_self_query_rate_limited(ip: str | None) -> bool:
    """Per-source-IP budget on the unauthenticated HELD self-query (#972).

    **Fails CLOSED, unlike the login throttle above.** That inversion is
    deliberate and is the only one in this module. The login throttle
    protects an endpoint whose real backstops are account lockout and a
    second factor, so degrading it to a no-op during a Redis outage costs
    little. This throttle IS the protection: behind it sits an
    unauthenticated endpoint that answers "which room is the device at this
    address in", and with Redis down an attacker inside the voice VLAN could
    otherwise walk the estate at full speed. A phone asks once a boot; the
    cost of failing closed is that it retries.
    """
    if not ip:
        return True
    key = f"e911_self_rl:{ip}"
    try:
        r = make_async_redis(settings.redis_url, socket_connect_timeout=2)
        try:
            count = await r.incr(key)
            if count == 1:
                await r.expire(key, _E911_SELF_RL_WINDOW_SECONDS)
            return int(count) > _E911_SELF_RL_MAX
        finally:
            await r.aclose()
    except Exception as exc:  # noqa: BLE001 — see the fail-closed note above
        logger.warning("e911_self_query_rate_limit_redis_unavailable", error=str(exc))
        return True


async def mfa_challenge_consume(jti: str | None) -> bool:
    """Atomically claim an MFA challenge ``jti``. Returns True if this is
    the first claim (caller may proceed), False if it was already consumed
    (replay / race — caller must reject).

    Fails open (True) when ``jti`` is missing (legacy token) or Redis is
    unavailable, preserving the prior stateless behaviour rather than
    blocking a legitimate MFA login during a Redis outage."""
    if not jti:
        return True
    key = f"mfa_challenge:{jti}:used"
    try:
        r = make_async_redis(settings.redis_url, socket_connect_timeout=2)
        try:
            # SET key 1 EX ttl NX — returns truthy only when the key did
            # not already exist, i.e. this is the first (winning) claim.
            ok = await r.set(key, "1", ex=_MFA_USED_TTL_SECONDS, nx=True)
            return bool(ok)
        finally:
            await r.aclose()
    except Exception as exc:  # noqa: BLE001 — never block MFA on a Redis blip
        logger.warning("mfa_replay_guard_redis_unavailable", error=str(exc))
        return True


class StepupThrottleUnavailable(Exception):
    """The step-up budget could not be read, so the step-up is refused rather
    than run unthrottled. See the module docstring."""


def _stepup_key(user_id: object) -> str:
    return f"stepup_fail:{user_id}"


async def stepup_password_blocked(user_id: object) -> bool:
    """True once this account has used up its wrong-answer budget. Checked
    BEFORE the credential, so a blocked caller learns nothing from a guess.

    Fails CLOSED: raises ``StepupThrottleUnavailable`` when Redis cannot
    answer, unlike the login throttle."""
    try:
        r = make_async_redis(settings.redis_url, socket_connect_timeout=2)
        try:
            count = await r.get(_stepup_key(user_id))
            return count is not None and int(count) >= _STEPUP_FAIL_MAX
        finally:
            await r.aclose()
    except Exception as exc:  # noqa: BLE001 — any Redis failure means "no budget to read"
        logger.warning("stepup_throttle_redis_unavailable", error=str(exc))
        raise StepupThrottleUnavailable from exc


async def record_stepup_password_failure(user_id: object) -> None:
    """Count one wrong step-up answer. Only failures count, so a user who
    gets it right is never slowed by their own successes.

    Best-effort: a failure to count is logged, not raised. The answer has
    already been refused, and the next attempt's ``stepup_password_blocked``
    fails closed if Redis is still down."""
    try:
        r = make_async_redis(settings.redis_url, socket_connect_timeout=2)
        try:
            count = await r.incr(_stepup_key(user_id))
            if count == 1:
                await r.expire(_stepup_key(user_id), _STEPUP_FAIL_WINDOW_SECONDS)
        finally:
            await r.aclose()
    except Exception as exc:  # noqa: BLE001 — throttle must never break the step-up
        logger.warning("stepup_throttle_redis_unavailable", error=str(exc))
