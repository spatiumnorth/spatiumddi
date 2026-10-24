"""Redis-backed throttles for the auth surface.

Two complements to the per-account lockout (#71):

* ``login_rate_limited`` — a per-source-IP attempt budget on
  ``/auth/login`` + ``/auth/login/mfa`` (#4). Account lockout needs a
  *valid username* to engage, so an attacker spraying usernames gets one
  free guess each before lockout triggers; an IP budget caps that. The
  budget is keyed by ``login_throttle_key``: an IPv4 address as itself, an
  IPv4-mapped IPv6 address as its IPv4 address, and any other IPv6 address
  as its /64, since one host is routinely handed a whole /64 and could
  otherwise take a fresh budget from every address in it.
* ``claim_login_attempt`` / ``refund_login_attempt`` — failed-password
  ceilings on ``/auth/login`` that no choice of source address escapes: one
  per submitted username (lower-cased, counted whether or not the account
  exists, so a refusal says nothing about which names are real), and one
  across the whole install. Modelled on the pairing claim: spent before the
  credential is checked, refunded on a right one.
* ``mfa_challenge_consume`` — single-use consumption of an MFA challenge
  ``jti`` so a captured (challenge + TOTP) pair can't be replayed inside
  the 5-minute token TTL (#7).

* ``mfa_challenge_spent`` / ``record_mfa_challenge_failure`` — a
  wrong-code budget per MFA challenge: after ``MFA_CHALLENGE_FAIL_MAX``
  wrong codes the challenge is dead and a fresh one needs the password
  again. Fails open like the other login throttles; the per-account
  budget on the user row (``account_lockout.MFA_FAIL_MAX``) is the bound
  that holds without Redis.

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

import hashlib
import ipaddress
from dataclasses import dataclass
from typing import Any

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

# Wrong codes one MFA challenge accepts before it is spent and the sign-in
# has to start again from the password.
MFA_CHALLENGE_FAIL_MAX = 3

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

# Failed-password ceilings on /auth/login: per submitted username and across
# the install, over one fixed window. The counts themselves are settings
# (``login_fail_max_per_username`` / ``login_fail_max_global``).
LOGIN_FAIL_WINDOW_SECONDS = 15 * 60
_LOGIN_FAIL_GLOBAL_KEY = "login_fail:global"

# Supervisor registration (#1356). The endpoint is unauthenticated by design:
# a new appliance proves itself with an 8-digit pairing code (~26.6 bits),
# and persistent codes can live for years. Wrong codes per source IP, and
# across the whole install so spreading guesses over many addresses does not
# help. Right codes are refunded, so a fleet rollout behind one NAT address
# never trips it.
PAIRING_FAIL_MAX_PER_IP = 10
PAIRING_FAIL_MAX_GLOBAL = 100
_PAIRING_FAIL_WINDOW_SECONDS = 15 * 60

# Spend one attempt, atomically. Each counter is INCR'd and given the window's
# expiry whenever it has none, in one script: a separate ``SET NX EX`` then
# ``INCR`` lets the key expire between the two, and the INCR then recreates it
# with no TTL, so that address (or, for the global key, the whole install)
# would stay throttled until someone deleted the key by hand.
#
# An address already over its own budget is NOT charged to the global one: a
# refused request checks no code, so counting it would let a single address
# exhaust the install-wide budget in a hundred requests and lock out every
# registration, right codes included. Likewise a request the global budget
# refuses gives the address its attempt back. Returns {ip_count, global_count},
# global_count = -1 when it was not charged.
_CLAIM_LUA = """
local function bump(key)
  local n = redis.call('INCR', key)
  if redis.call('TTL', key) < 0 then
    redis.call('EXPIRE', key, ARGV[1])
  end
  return n
end
local ip = bump(KEYS[1])
if ip > tonumber(ARGV[2]) then
  return {ip, -1}
end
local g = bump(KEYS[2])
if g > tonumber(ARGV[3]) then
  ip = redis.call('DECR', KEYS[1])
end
return {ip, g}
"""

# Decrement only a key that still exists and is above zero, so a refund that
# arrives after the window expired cannot leave a counter with no TTL.
_REFUND_LUA = """
local v = redis.call('GET', KEYS[1])
if v and tonumber(v) > 0 then
  return redis.call('DECR', KEYS[1])
end
return 0
"""

# INCR a fixed-window counter and open its window when it has none, in ONE
# script (#2294). ``INCR`` then a separate ``EXPIRE`` (only when the result is
# 1) lets a crash, timeout or dropped connection between the two leave the key
# counting with no TTL; every later call then sees a count above 1, never sets
# the expiry, and that address / user is throttled forever. Here the expiry is
# set whenever the key has none, so a TTL-less key is also repaired by the next
# call. The window still starts at the first hit and is not slid by later ones.
_INCR_WINDOW_LUA = """
local n = redis.call('INCR', KEYS[1])
if redis.call('TTL', KEYS[1]) < 0 then
  redis.call('EXPIRE', KEYS[1], ARGV[1])
end
return n
"""


async def incr_with_window(r: Any, key: str, window_seconds: int) -> int:
    """Count one hit against ``key`` in a fixed ``window_seconds`` window and
    return the new count. Atomic; never leaves ``key`` without an expiry.
    Raises whatever the Redis client raises -- each caller picks its own
    fail-open / fail-closed answer."""
    return int(await r.eval(_INCR_WINDOW_LUA, 1, key, window_seconds))


def login_throttle_key(ip: str) -> str:
    """The unit the per-source login budget counts against.

    IPv4: the address. IPv4-mapped IPv6 (``::ffff:a.b.c.d``): the IPv4
    address, so a dual-stack listener does not give one client two budgets.
    Other IPv6: the /64 it sits in — SLAAC and privacy addressing hand a
    single host a whole /64, so per-/128 keying gave it ~2^64 budgets. A
    value that is not an address is used as-is."""
    try:
        addr = ipaddress.ip_address(ip.strip())
    except ValueError:
        return ip
    if isinstance(addr, ipaddress.IPv6Address):
        if addr.ipv4_mapped is not None:
            return str(addr.ipv4_mapped)
        return str(ipaddress.IPv6Network((addr, 64), strict=False))
    return str(addr)


async def login_rate_limited(ip: str | None) -> bool:
    """Increment the per-source login counter and return True once it
    exceeds the window budget. The source is ``login_throttle_key(ip)``.
    Fails open (False) when ``ip`` is unknown or Redis is unavailable."""
    if not ip:
        return False
    key = f"login_rl:{login_throttle_key(ip)}"
    try:
        r = make_async_redis(settings.redis_url, socket_connect_timeout=2)
        try:
            count = await incr_with_window(r, key, _LOGIN_RL_WINDOW_SECONDS)
            return int(count) > _LOGIN_RL_MAX
        finally:
            await r.aclose()
    except Exception as exc:  # noqa: BLE001 — throttle must never break login
        logger.warning("login_rate_limit_redis_unavailable", error=str(exc))
        return False


# Spend one sign-in attempt from the username and install-wide budgets, in
# one script (see ``_CLAIM_LUA`` for the shape). KEYS = {username, global};
# ARGV = {window, username max, global max}, where a max of 0 or less turns
# that ceiling off and its key is never touched. A username already over its
# own budget is not charged to the install-wide one, so hammering one name
# cannot spend everyone's budget on its own; a request the install-wide
# budget refuses gives the username its attempt back.
# Returns {allowed, username_charged, global_charged, retry_after}.
_LOGIN_CLAIM_LUA = """
local function bump(key)
  local n = redis.call('INCR', key)
  if redis.call('TTL', key) < 0 then
    redis.call('EXPIRE', key, ARGV[1])
  end
  return n
end
local mu = tonumber(ARGV[2])
local mg = tonumber(ARGV[3])
local uc = 0
if mu > 0 then
  if bump(KEYS[1]) > mu then
    return {0, 0, 0, redis.call('TTL', KEYS[1])}
  end
  uc = 1
end
if mg > 0 then
  if bump(KEYS[2]) > mg then
    if uc == 1 then
      redis.call('DECR', KEYS[1])
    end
    return {0, 0, 0, redis.call('TTL', KEYS[2])}
  end
  return {1, uc, 1, 0}
end
return {1, uc, 0, 0}
"""


@dataclass(frozen=True)
class LoginClaim:
    """The outcome of ``claim_login_attempt``. ``allowed`` False carries the
    seconds until the refusing window ends; the ``*_charged`` flags say what
    ``refund_login_attempt`` has to give back."""

    allowed: bool
    retry_after: int = 0
    username_charged: bool = False
    global_charged: bool = False


_LOGIN_CLAIM_OPEN = LoginClaim(allowed=True)


def _login_fail_keys(username: str) -> tuple[str, str]:
    # Lower-cased so ``Admin`` and ``admin`` share a budget, and hashed so the
    # key length is bounded whatever was submitted.
    digest = hashlib.sha256(username.lower().encode("utf-8")).hexdigest()[:32]
    return f"login_fail:user:{digest}", _LOGIN_FAIL_GLOBAL_KEY


async def claim_login_attempt(username: str) -> LoginClaim:
    """Spend one ``/auth/login`` attempt from the per-username and the
    install-wide failure budgets, before the credential is checked, so
    concurrent guesses cannot all read an under-budget count. The caller
    gives it back with ``refund_login_attempt`` when the password was right,
    so only failures stay counted.

    The username budget is keyed by the name as submitted (lower-cased),
    existing or not: a refusal is the same for a real account and an
    invented one.

    Fails OPEN, like the per-source budget: with Redis unreachable every
    attempt is allowed and nothing is charged, leaving account lockout and
    the second factor as the bounds."""
    max_user = settings.login_fail_max_per_username
    max_global = settings.login_fail_max_global
    if max_user <= 0 and max_global <= 0:
        return _LOGIN_CLAIM_OPEN
    user_key, global_key = _login_fail_keys(username)
    try:
        r: Any = make_async_redis(settings.redis_url, socket_connect_timeout=2)
        try:
            allowed, user_charged, global_charged, ttl = await r.eval(
                _LOGIN_CLAIM_LUA,
                2,
                user_key,
                global_key,
                LOGIN_FAIL_WINDOW_SECONDS,
                max_user,
                max_global,
            )
        finally:
            await r.aclose()
    except Exception as exc:  # noqa: BLE001 — throttle must never break login
        logger.warning("login_fail_ceiling_redis_unavailable", error=str(exc))
        return _LOGIN_CLAIM_OPEN
    if int(allowed):
        return LoginClaim(
            allowed=True,
            username_charged=bool(int(user_charged)),
            global_charged=bool(int(global_charged)),
        )
    ttl = int(ttl)
    # Too long a Retry-After only delays a retry; too short sends the client
    # back while it is still refused.
    return LoginClaim(allowed=False, retry_after=ttl if ttl > 0 else LOGIN_FAIL_WINDOW_SECONDS)


async def refund_login_attempt(username: str, claim: LoginClaim) -> None:
    """Give back what ``claim_login_attempt`` charged for an attempt whose
    password was right. Best-effort: a lost refund costs one attempt."""
    user_key, global_key = _login_fail_keys(username)
    keys = [
        k
        for k, charged in ((user_key, claim.username_charged), (global_key, claim.global_charged))
        if charged
    ]
    if not keys:
        return
    try:
        r: Any = make_async_redis(settings.redis_url, socket_connect_timeout=2)
        try:
            for key in keys:
                await r.eval(_REFUND_LUA, 1, key)
        finally:
            await r.aclose()
    except Exception as exc:  # noqa: BLE001 — a lost refund only costs one attempt
        logger.warning("login_fail_ceiling_redis_unavailable", error=str(exc))


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
            count = await incr_with_window(r, key, _E911_SELF_RL_WINDOW_SECONDS)
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
    key = _mfa_challenge_used_key(jti)
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


def _mfa_challenge_used_key(jti: str) -> str:
    return f"mfa_challenge:{jti}:used"


def _mfa_challenge_fail_key(jti: str) -> str:
    return f"mfa_challenge:{jti}:fails"


async def mfa_challenge_spent(jti: str | None) -> bool:
    """True when the challenge has already been redeemed or has used up its
    wrong-code budget. Checked before the code, so a spent challenge learns
    nothing from another guess.

    Fails open (False) when ``jti`` is missing or Redis is unavailable; the
    per-account budget on the user row still bounds guessing then."""
    if not jti:
        return False
    try:
        r = make_async_redis(settings.redis_url, socket_connect_timeout=2)
        try:
            if await r.exists(_mfa_challenge_used_key(jti)):
                return True
            fails = await r.get(_mfa_challenge_fail_key(jti))
            return fails is not None and int(fails) >= MFA_CHALLENGE_FAIL_MAX
        finally:
            await r.aclose()
    except Exception as exc:  # noqa: BLE001 — the DB-side budget is the hard bound
        logger.warning("mfa_challenge_budget_redis_unavailable", error=str(exc))
        return False


async def record_mfa_challenge_failure(jti: str | None) -> bool:
    """Count one wrong code against this challenge. Returns True iff the
    challenge is now spent, in which case it is also marked used so it can
    never be redeemed. Best-effort, like ``mfa_challenge_spent``."""
    if not jti:
        return False
    key = _mfa_challenge_fail_key(jti)
    try:
        r = make_async_redis(settings.redis_url, socket_connect_timeout=2)
        try:
            # Open the window before the INCR (which keeps the TTL) so the
            # counter can never be left without an expiry.
            await r.set(key, 0, ex=_MFA_USED_TTL_SECONDS, nx=True)
            count = int(await r.incr(key))
            if count >= MFA_CHALLENGE_FAIL_MAX:
                await r.set(_mfa_challenge_used_key(jti), "1", ex=_MFA_USED_TTL_SECONDS)
                return True
            return False
        finally:
            await r.aclose()
    except Exception as exc:  # noqa: BLE001 — the DB-side budget is the hard bound
        logger.warning("mfa_challenge_budget_redis_unavailable", error=str(exc))
        return False


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


# Give one claimed attempt back, but only while the window that counted it is
# still open: a DECR on an expired key would recreate it at -1 with no TTL,
# and every later INCR would then accumulate on a key that never expires.
_STEPUP_REFUND_LUA = """
if redis.call('EXISTS', KEYS[1]) == 1 then
  return redis.call('DECR', KEYS[1])
end
return 0
"""


async def claim_stepup_attempt(user_id: object) -> bool:
    """Spend one attempt from the budget BEFORE the answer is checked, and say
    whether it was within the budget (#1354).

    ``stepup_password_blocked`` + ``record_stepup_password_failure`` is a
    read-then-count: a burst of concurrent requests all read the same
    under-budget count before any of them records, so the budget bounds
    sequential guessing only. That matters little for a bcrypt-checked
    password and a lot for a 6-digit code, so the enrolment verify claims
    the attempt atomically instead, and refunds it on success
    (``refund_stepup_attempt``) so only wrong answers stay counted.

    The count and its expiry are set by one script (``incr_with_window``), so
    a key can never be left counting without an expiry.

    Fails CLOSED, like ``stepup_password_blocked``."""
    key = _stepup_key(user_id)
    try:
        r = make_async_redis(settings.redis_url, socket_connect_timeout=2)
        try:
            count = await incr_with_window(r, key, _STEPUP_FAIL_WINDOW_SECONDS)
            return int(count) <= _STEPUP_FAIL_MAX
        finally:
            await r.aclose()
    except Exception as exc:  # noqa: BLE001 — any Redis failure means "no budget to spend"
        logger.warning("stepup_throttle_redis_unavailable", error=str(exc))
        raise StepupThrottleUnavailable from exc


async def refund_stepup_attempt(user_id: object) -> None:
    """Give back an attempt ``claim_stepup_attempt`` spent on a right answer.
    Best-effort: failing to refund costs the user one attempt, nothing more."""
    try:
        # ``Any``: redis-py types ``eval`` as sync-or-async (agent_bundles does
        # the same).
        r: Any = make_async_redis(settings.redis_url, socket_connect_timeout=2)
        try:
            await r.eval(_STEPUP_REFUND_LUA, 1, _stepup_key(user_id))
        finally:
            await r.aclose()
    except Exception as exc:  # noqa: BLE001 — a lost refund only costs one attempt
        logger.warning("stepup_throttle_redis_unavailable", error=str(exc))


async def stepup_block_seconds_left(user_id: object) -> int:
    """Seconds until a spent step-up budget resets, for ``Retry-After``.

    Falls back to the full window when Redis cannot say, or the key has no
    TTL: a ``Retry-After`` that is too long only delays a retry, while one
    that is too short sends the client back while it is still blocked."""
    try:
        r = make_async_redis(settings.redis_url, socket_connect_timeout=2)
        try:
            ttl = int(await r.ttl(_stepup_key(user_id)))
        finally:
            await r.aclose()
    except Exception as exc:  # noqa: BLE001 — only the header depends on it
        logger.warning("stepup_throttle_redis_unavailable", error=str(exc))
        return _STEPUP_FAIL_WINDOW_SECONDS
    return ttl if ttl > 0 else _STEPUP_FAIL_WINDOW_SECONDS


async def record_stepup_password_failure(user_id: object) -> None:
    """Count one wrong step-up answer. Only failures count, so a user who
    gets it right is never slowed by their own successes.

    Best-effort: a failure to count is logged, not raised. The answer has
    already been refused, and the next attempt's ``stepup_password_blocked``
    fails closed if Redis is still down."""
    try:
        r = make_async_redis(settings.redis_url, socket_connect_timeout=2)
        try:
            await incr_with_window(r, _stepup_key(user_id), _STEPUP_FAIL_WINDOW_SECONDS)
        finally:
            await r.aclose()
    except Exception as exc:  # noqa: BLE001 — throttle must never break the step-up
        logger.warning("stepup_throttle_redis_unavailable", error=str(exc))


class PairingThrottleUnavailable(Exception):
    """The pairing-attempt budget could not be read; refuse the attempt."""


def _pairing_keys(ip: str | None) -> tuple[str, str]:
    return f"pair_rl:ip:{ip or 'unknown'}", "pair_rl:global"


async def claim_pairing_attempt(ip: str | None) -> tuple[bool, int, int]:
    """Spend one supervisor-registration attempt (#1356).

    Returns ``(allowed, ip_failures, global_failures)``, each counting this
    attempt; ``global_failures`` is ``-1`` when the address was already over
    its own budget and the install-wide one was not charged. Spent before the
    code is looked up, so concurrent guesses cannot all read an under-budget
    count; ``refund_pairing_attempt`` gives it back when the code was right.
    One Lua script, so a counter is never left without an expiry (see
    ``_CLAIM_LUA``).

    Fails CLOSED (``PairingThrottleUnavailable``): this budget is the only
    thing between an unauthenticated caller and the code space.
    """
    ip_key, global_key = _pairing_keys(ip)
    try:
        r: Any = make_async_redis(settings.redis_url, socket_connect_timeout=2)
        try:
            ip_count, global_count = await r.eval(
                _CLAIM_LUA,
                2,
                ip_key,
                global_key,
                _PAIRING_FAIL_WINDOW_SECONDS,
                PAIRING_FAIL_MAX_PER_IP,
                PAIRING_FAIL_MAX_GLOBAL,
            )
        finally:
            await r.aclose()
    except Exception as exc:  # noqa: BLE001 — any Redis failure means "no budget to spend"
        logger.warning("pairing_throttle_redis_unavailable", error=str(exc))
        raise PairingThrottleUnavailable from exc
    ip_count, global_count = int(ip_count), int(global_count)
    allowed = 0 <= global_count <= PAIRING_FAIL_MAX_GLOBAL and ip_count <= PAIRING_FAIL_MAX_PER_IP
    return allowed, ip_count, global_count


async def refund_pairing_attempt(ip: str | None) -> None:
    """Give back the attempt a successful registration spent. Best-effort."""
    try:
        r: Any = make_async_redis(settings.redis_url, socket_connect_timeout=2)
        try:
            for key in _pairing_keys(ip):
                await r.eval(_REFUND_LUA, 1, key)
        finally:
            await r.aclose()
    except Exception as exc:  # noqa: BLE001 — a lost refund only costs one attempt
        logger.warning("pairing_throttle_redis_unavailable", error=str(exc))
