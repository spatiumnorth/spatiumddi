"""Group/role-based permission checks.

The shape of a permission stored in `Role.permissions` (JSONB) is::

    {"action": "<action>", "resource_type": "<resource_type>", "resource_id": "<uuid?>"}

- ``action``: ``read``, ``write``, ``delete``, ``admin`` (``admin`` implies
  the other three on that resource_type), or the wildcard ``"*"``.
- ``resource_type``: one of the strings enumerated in ``docs/PERMISSIONS.md``
  (e.g. ``ip_space``, ``dns_zone``), or the wildcard ``"*"``.
- ``resource_id``: optional. When absent/None the permission applies to every
  instance of ``resource_type``; when set it scopes to that single UUID.

Superadmin (`User.is_superadmin=True`) short-circuits every check and is never
denied. This is enforced both here and in the FastAPI dependency factories.

Two entry points are exported:

* ``user_has_permission`` — pure helper, safe to call from inside a handler
  after a DB lookup (fine-grained, per-row gate).
* ``require_permission`` — dependency factory for FastAPI. Pass it into
  ``Depends(...)`` / ``dependencies=[Depends(...)]`` at route or router scope.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Annotated, NoReturn
from uuid import UUID

import structlog
from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import CurrentUser, get_db
from app.core.request_meta import clean_user_agent, get_trusted_client_ip
from app.models.audit import AuditLog
from app.models.auth import User

logger = structlog.get_logger(__name__)

# Actions that are implied by the "admin" action.
_ADMIN_IMPLIES = frozenset({"read", "write", "delete", "admin"})

# Resource type gate for VRF CRUD (issue #86). The "manage_vrfs"
# label in design docs corresponds to ``admin`` on this resource_type
# in the underlying RBAC grammar — the API uses
# ``require_resource_permission("vrf")``. The Network Editor builtin
# role grants ``admin`` on this type; superadmin always bypasses.
RESOURCE_TYPE_VRF = "vrf"

# Appliance management surface (issue #134, Phase 4). Every
# /api/v1/appliance/* router gates on ``read`` or ``admin`` against
# this resource_type. The "Appliance Operator" builtin role grants
# ``admin``; the read-only "Appliance Viewer" role can be added later
# if a NOC team wants visibility without lifecycle control.
#
# Note: the gate is independent from ``settings.appliance_mode``.
# appliance_mode is a deployment-time flag (is the API running on
# the SpatiumDDI OS appliance?); the permission is an authorization
# flag (does THIS user get to drive it?). The router stays mounted
# either way; on a non-appliance deploy every endpoint will 404 or
# return empty data because the underlying OS surfaces aren't there.
RESOURCE_TYPE_APPLIANCE = "appliance"

# Two-person approval workflow surface (issue #62). The
# /api/v1/change-requests/* router gates on ``read`` (queue + history)
# and the new ``approve`` action (decide a request) against this
# resource_type. The "Change Approver" builtin role grants both.
#
# ``approve`` is a NEW action string deliberately NOT covered by the
# ``admin`` implication (``_ADMIN_IMPLIES`` lists only read/write/delete/
# admin): a wildcard/admin grant on ``change_request`` does NOT confer
# approve. Approve must be granted explicitly — a two-person rule whose
# approve capability rides along with generic admin isn't a two-person
# rule. The approve endpoint additionally enforces, server-side, that the
# approver holds the *underlying operation's* required_permission and is
# not the requester.
RESOURCE_TYPE_CHANGE_REQUEST = "change_request"

# Self-service request portal surface (issue #696). The /api/v1/requests/*
# router gates ``write`` (submit a request) and ``read`` (see your own
# requests) against this resource_type.
#
# ``write`` rather than a bespoke ``create`` verb: the grammar's
# ``_ADMIN_IMPLIES`` covers only read/write/delete/admin, so a ``create``
# action would silently NOT be conferred by an ``admin`` grant on this type —
# an operator granting ``admin,provisioning_request`` would get 403 on submit,
# which is the opposite of what they asked for.
#
# This is the LOW-privilege half of the workflow and is meant to be granted
# broadly — the "Requester" builtin role grants exactly these two and nothing
# else. Holding it confers no ability to provision anything: a submitted
# request only ever becomes a change to the platform when a *different*
# operator who holds the underlying operation's own permission approves it,
# enforced by the shared #62 approve spine.
#
# Deciding a portal request reuses ``approve,change_request`` rather than
# introducing a second approve capability — an operator who is trusted to
# approve is trusted to approve, and one queue permission is easier to reason
# about than two. The catalog allow-list (services/requests/catalog.py) is
# what bounds which operations can reach that approver at all.
RESOURCE_TYPE_PROVISIONING_REQUEST = "provisioning_request"


def _action_matches(granted: str, requested: str) -> bool:
    """Return True if a granted `action` string covers the requested action."""
    if granted == "*" or granted == requested:
        return True
    if granted == "admin" and requested in _ADMIN_IMPLIES:
        return True
    return False


def _resource_type_matches(granted: str, requested: str) -> bool:
    return granted == "*" or granted == requested


def _resource_id_matches(granted: str | None, requested: str | None) -> bool:
    """Granted=None means any instance. Otherwise must be equal."""
    if granted is None or granted == "" or granted == "*":
        return True
    if requested is None:
        # Can't match a scoped grant when the check is unscoped — this
        # prevents "granted scope X but action asks about the whole type".
        return False
    return str(granted) == str(requested)


def _token_grants_for(user: User) -> list[dict]:
    """Active API-token resource grants stashed on the user by the auth dep
    (issue #374). Empty for session/JWT requests and for tokens without a
    resource binding — those are unrestricted (only their coarse ``scopes``
    + the owner's RBAC apply)."""
    grants = getattr(user, "_api_token_resource_grants", None) or []
    return [g for g in grants if isinstance(g, dict)]


def _token_grants_allow(
    grants: list[dict], action: str, resource_type: str, req_rid: str | None
) -> bool:
    """Intersection rule for a resource-scoped token (issue #374).

    A token can only ever NARROW its owner. ``user_has_permission`` calls this
    only after the owner's RBAC already allowed the request, so this purely
    decides whether the *token* also permits it:

    * **Coarse check** (``req_rid is None`` — the router-level method gate):
      pass if any grant covers (action, resource_type) regardless of the
      grant's own resource_id. This lets a subnet-scoped token through the
      coarse gate so the request reaches the handler, where the per-row
      ``token_scope_allows`` enforces the specific instance. A wildcard grant
      (``*``/``*``) always passes.
    * **Scoped check** (``req_rid`` set — a per-row gate): a grant must match
      action + resource_type + resource_id (grant resource_id None/``*`` = any
      instance of that type, else exact match).

    Write implies read for token grants: a token granted ``write`` / ``delete``
    on a resource can also ``read`` it (you can't sensibly mutate what you can't
    read), so a ``write``-only resource token isn't locked out of GET-ing its
    own bound resource.
    """
    for g in grants:
        g_action = g.get("action", "")
        action_ok = _action_matches(g_action, action) or (
            action == "read" and g_action in ("write", "delete")
        )
        if not action_ok:
            continue
        if not _resource_type_matches(g.get("resource_type", ""), resource_type):
            continue
        if req_rid is None:
            return True
        if _resource_id_matches(g.get("resource_id"), req_rid):
            return True
    return False


def token_scope_allows(user: User, resource_type: str, resource_id: str | UUID | None) -> bool:
    """Per-row token-binding gate for handlers (issue #374).

    Returns ``True`` for any request whose credential carries NO resource
    grants (sessions, plain tokens) — so normal callers are completely
    unaffected. For a resource-scoped token, returns ``True`` only when a
    grant covers (resource_type, resource_id). Call this inside a handler
    once the target resource is known, e.g.::

        if not token_scope_allows(user, "subnet", subnet.id):
            raise HTTPException(403, "API token is not scoped to this subnet")
    """
    grants = _token_grants_for(user)
    if not grants:
        return True
    req_rid = str(resource_id) if resource_id is not None else None
    for g in grants:
        if not _resource_type_matches(g.get("resource_type", ""), resource_type):
            continue
        if _resource_id_matches(g.get("resource_id"), req_rid):
            return True
    return False


def token_scoped_resource_ids(user: User, resource_type: str) -> set[str] | None:
    """Resource IDs a resource-scoped token is bound to for ``resource_type``.

    Companion to :func:`token_scope_allows` for *list* endpoints (issue #523):
    a by-id read gates with ``token_scope_allows``, but a list must instead
    narrow its result set to the bound instances or a subnet-scoped token can
    enumerate the whole tree via ``GET /subnets`` / ``/blocks`` / ``/spaces``.
    Returns:

    * ``None`` — the caller carries no resource grants (session / plain token),
      OR holds a wildcard grant covering this ``resource_type`` (any instance).
      List endpoints run unfiltered, exactly as before.
    * a (possibly empty) ``set`` of resource-id strings — a resource-scoped
      token; only these instances are visible. An empty set means the token is
      bound only to *other* resource types and sees none of this one.
    """
    grants = _token_grants_for(user)
    if not grants:
        return None
    ids: set[str] = set()
    for g in grants:
        if not _resource_type_matches(g.get("resource_type", ""), resource_type):
            continue
        rid = g.get("resource_id")
        if rid is None or rid == "" or rid == "*":
            # Wildcard grant on this type → every instance is in scope.
            return None
        ids.add(str(rid))
    return ids


def is_effective_superadmin(user: User) -> bool:
    """Whether the user is a superadmin for gate-style checks.

    Two paths qualify:

    * **Legacy column** — ``User.is_superadmin=True`` set directly on the
      row (seeded ``admin`` account, anyone explicitly flagged in
      ``users/router.py``'s admin form).
    * **RBAC wildcard** — the user belongs to a group whose role carries
      a ``{action: "*", resource_type: "*"}`` permission (the built-in
      ``Superadmin`` role + any custom clone of it).

    Without the RBAC path, users provisioned via LDAP / OIDC / SAML and
    mapped into a Superadmin-role group pass every ``require_permission``
    gate but get 403 on the per-endpoint local ``_require_superadmin``
    helpers — closes that split-brain (issue #190).

    This is intentionally separate from :func:`user_has_permission`:
    inactive users are admitted here when the legacy flag is set so a
    disabled superadmin can still reach the diagnostic surfaces an
    operator might need during incident triage. Per-permission checks
    still gate on ``user.is_active``.
    """
    # A resource-scoped token (issue #374) is never a superadmin, even when
    # owned by the seeded ``admin`` — skip the legacy-flag shortcut so the
    # wildcard intersection in user_has_permission decides (a non-wildcard
    # token grant won't match ``*``/``*`` and correctly fails the gate).
    if getattr(user, "is_superadmin", False) and not _token_grants_for(user):
        return True
    return user_has_permission(user, "*", "*")


def user_has_permission(
    user: User,
    action: str,
    resource_type: str,
    resource_id: str | UUID | None = None,
) -> bool:
    """Synchronous permission check.

    Call this from inside a handler once you've loaded the specific resource
    and have its UUID, to enforce per-row scoping. For coarse-grained gates
    use :func:`require_permission`.
    """
    if not user.is_active:
        return False

    req_rid = str(resource_id) if resource_id is not None else None

    # Resolve the owner's RBAC verdict first (issue #374 intersection: a token
    # can only narrow, so the owner must allow before the token is consulted).
    rbac_allowed = _user_rbac_allows(user, action, resource_type, req_rid)
    if not rbac_allowed:
        return False

    # Token narrowing (#374): when the active credential is a resource-scoped
    # token, the request must ALSO be covered by its grants — intersection.
    token_grants = _token_grants_for(user)
    if token_grants and not _token_grants_allow(token_grants, action, resource_type, req_rid):
        return False
    return True


def _user_rbac_allows(
    user: User,
    action: str,
    resource_type: str,
    req_rid: str | None,
    *,
    include_time_bound: bool = True,
) -> bool:
    """The owning user's static-role + time-bound-grant verdict (no token
    narrowing — that's layered on in :func:`user_has_permission`).

    ``include_time_bound=False`` answers from static roles (and the legacy
    flag) alone, for :func:`caller_can_grant`."""
    if user.is_superadmin:
        return True

    for group in user.groups:
        for role in group.roles:
            for perm in role.permissions or []:
                if not isinstance(perm, dict):
                    continue
                if not _action_matches(perm.get("action", ""), action):
                    continue
                if not _resource_type_matches(perm.get("resource_type", ""), resource_type):
                    continue
                if not _resource_id_matches(perm.get("resource_id"), req_rid):
                    continue
                return True

    # Additive union over any live time-bound grants (issue #65). The auth
    # dependency stashes the caller's active grants on this attribute after
    # loading them from ``time_bound_grant`` (filtered to revoked_at IS NULL
    # AND expires_at > now()). A temporary grant can only widen access — it
    # never removes a static role grant. The same _action_/_resource_type_/
    # _resource_id_ predicates apply so a grant evaluates identically to a
    # role permission with the same triple.
    if not include_time_bound:
        return False
    for grant in getattr(user, "_active_time_bound_grants", None) or []:
        if not _action_matches(getattr(grant, "action", ""), action):
            continue
        if not _resource_type_matches(getattr(grant, "resource_type", ""), resource_type):
            continue
        if not _resource_id_matches(getattr(grant, "resource_id", None), req_rid):
            continue
        return True
    return False


def effective_grants(user: User) -> list[dict]:
    """Assemble the deduped, effective permission triples ``user`` resolves to.

    Mirrors the resolution path of :func:`user_has_permission` exactly so the
    list answers "which (action, resource_type, resource_id) does this caller
    actually get?" for self-introspection (``GET /auth/me/permissions``):

    * static role permissions (``group → role → permissions``)
    * ∪ live time-bound grants (issue #65, stashed on
      ``_active_time_bound_grants`` by the auth dep)
    * **then narrowed** by the active credential's API-token resource grants
      (issue #374) — a resource-scoped token only ever shrinks the owner's set,
      so the returned list is the intersection that ``user_has_permission``
      enforces.

    Resource ids are normalised through :func:`_perm_triple` so ``""`` / ``"*"``
    collapse to ``None`` (any-instance). A legacy-column superadmin
    (``user.is_superadmin``) always gets a synthetic ``{*, *}`` entry added
    before role processing so the list is non-empty and backs the client-side
    ``is_superadmin`` short-circuit; if a role already carries the RBAC wildcard
    the set-dedup makes the synthetic add a harmless no-op. Returns ``[]`` for an
    inactive user (mirrors ``user_has_permission`` failing closed).

    Pure / synchronous — reads only attributes already stashed on ``user`` by
    the auth dependency; performs no DB or network IO.
    """
    if not user.is_active:
        return []

    triples: set[tuple[str, str, str | None]] = set()

    # Legacy-column superadmin: surface the wildcard explicitly so the
    # introspection payload is non-empty. Added unconditionally before role
    # processing — if a role already carries ``{*, *}`` the set-dedup makes
    # this a harmless no-op.
    if user.is_superadmin:
        triples.add(("*", "*", None))

    # Static role permissions.
    for group in user.groups:
        for role in group.roles:
            for perm in role.permissions or []:
                triple = _perm_triple(perm)
                if triple is not None:
                    triples.add(triple)

    # Additive union over any live time-bound grants (issue #65).
    for grant in getattr(user, "_active_time_bound_grants", None) or []:
        triple = _perm_triple(grant)
        if triple is not None:
            triples.add(triple)

    # Token narrowing (issue #374): when the active credential is a
    # resource-scoped token, intersect the RBAC set with the token's grants so
    # ``permissionMatch`` over the returned list equals ``user_has_permission``
    # for EVERY (action, resource_type, resource_id).
    #
    # The scoped path (``rid is not None``) reuses ``_token_grants_allow``'s
    # exact check verbatim. The any-instance path (``rid is None``) must NOT be
    # kept verbatim — ``_token_grants_allow`` returns True for a None req_rid as
    # a COARSE router gate (so the request reaches the handler), but enforcement
    # via per-row ``token_scope_allows`` is narrower. Keeping the broad
    # ``(a, ty, None)`` triple here over-reports: it would claim any-instance
    # access the token doesn't actually grant. So for a None-rid RBAC triple we
    # substitute the token's own narrower scoped ids: if a covering grant is
    # itself any-instance (None/``""``/``*``) we keep ``(a, ty, None)``; for each
    # scoped covering grant we emit ``(a, ty, <grant.resource_id>)`` instead. A
    # grant "covers" the action under the same rule ``_token_grants_allow`` uses
    # (``_action_matches`` OR the read-implies-write/delete relaxation).
    token_grants = _token_grants_for(user)
    if token_grants:
        narrowed: set[tuple[str, str, str | None]] = set()
        for action, resource_type, rid in triples:
            if rid is not None:
                # Scoped RBAC triple — keep iff the token also permits that
                # exact instance (unchanged exact-scope intersection).
                if _token_grants_allow(token_grants, action, resource_type, rid):
                    narrowed.add((action, resource_type, rid))
                continue
            # Any-instance RBAC triple — narrow by each covering token grant.
            for g in token_grants:
                g_action = g.get("action", "")
                action_ok = _action_matches(g_action, action) or (
                    action == "read" and g_action in ("write", "delete")
                )
                if not action_ok:
                    continue
                if not _resource_type_matches(g.get("resource_type", ""), resource_type):
                    continue
                g_rid = g.get("resource_id")
                if g_rid is None or g_rid == "" or g_rid == "*":
                    # Token grant is itself any-instance — the broad triple holds.
                    narrowed.add((action, resource_type, None))
                else:
                    # Substitute the token's narrower scoped id.
                    narrowed.add((action, resource_type, str(g_rid)))
        triples = narrowed

    ordered = sorted(triples, key=lambda t: (t[1], t[0], t[2] or ""))
    return [
        {"action": action, "resource_type": resource_type, "resource_id": rid}
        for action, resource_type, rid in ordered
    ]


# ── Privilege ceiling for delegated role / group editing ──────────────────────
#
# SECURITY (#400, finding C4): a non-superadmin holding a delegated
# ``admin:role`` (+``admin:group``) capability could previously mint a role
# carrying ``{action:"*", resource_type:"*"}`` (or any permission the caller
# does not themselves hold) and self-assign it, escalating to effective
# superadmin. The default install does not delegate ``admin:role`` to
# non-superadmins, so it is not exploitable out of the box — but the delegated
# capability was silently unbounded.
#
# ``caller_can_grant`` enforces a privilege ceiling: a non-superadmin may only
# author / attach permission triples they already hold themselves, and may
# never mint a wildcard (``*`` action OR ``*`` resource_type) permission.
# Effective superadmins bypass the ceiling entirely so the platform owner can
# still build arbitrary roles. Callers (roles + groups routers) pre-screen the
# requested permission set with this helper and 403 on any entry that exceeds
# the caller's own grants.


def _perm_triple(perm: object) -> tuple[str, str, str | None] | None:
    """Normalise a permission entry (dict or grant-like object) into a
    ``(action, resource_type, resource_id)`` triple, or ``None`` if the shape
    is unrecognised. Empty-string / ``"*"`` resource_id collapses to ``None``
    (any-instance)."""
    if isinstance(perm, dict):
        action = perm.get("action", "")
        resource_type = perm.get("resource_type", "")
        resource_id = perm.get("resource_id")
    else:
        action = getattr(perm, "action", "")
        resource_type = getattr(perm, "resource_type", "")
        resource_id = getattr(perm, "resource_id", None)
    if not isinstance(action, str) or not isinstance(resource_type, str):
        return None
    rid = resource_id if isinstance(resource_id, str) and resource_id not in ("", "*") else None
    return (action, resource_type, rid)


def caller_can_grant(user: User, perms: object) -> bool:
    """Whether ``user`` is allowed to author / attach the permission set ``perms``.

    ``perms`` is an iterable of permission entries — either ``dict``s in the
    ``Role.permissions`` JSONB shape or objects exposing ``action`` /
    ``resource_type`` / ``resource_id`` attributes (Pydantic
    ``PermissionEntry``, ``TimeBoundGrant`` rows).

    Rules (privilege ceiling, #400 / C4):

    * Effective superadmins may grant anything — return ``True`` immediately.
    * Any wildcard permission (``action == "*"`` OR ``resource_type == "*"``)
      may only be granted by an effective superadmin → ``False`` for everyone
      else.
    * Every other entry must be one the caller *already holds* (verified via
      :func:`user_has_permission` with the same triple). A caller cannot grant
      a permission they don't possess, so the resulting role can never widen
      the caller's own effective access.
    * ...and holds through a static role, not only through a live time-bound
      grant. Granting is durable (a role, a membership, a fresh grant with its
      own expiry), so a permission held until a deadline must not be turnable
      into one held after it.

    A malformed / unrecognised entry is treated as un-grantable (``False``) so
    a bad shape can't sneak past the ceiling.
    """
    if is_effective_superadmin(user):
        return True
    for perm in perms:
        triple = _perm_triple(perm)
        if triple is None:
            return False
        action, resource_type, rid = triple
        # No wildcard minting for non-superadmins — a `*` on either axis would
        # grant access beyond what the caller can express via concrete holds.
        if action == "*" or resource_type == "*":
            return False
        # The caller must already hold this exact (action, resource_type[, id]),
        # and hold it through a static role: a time-bound grant is not a
        # ceiling to grant from, or it would outlive its own expiry.
        if not user_has_permission(user, action, resource_type, rid):
            return False
        if not _user_rbac_allows(user, action, resource_type, rid, include_time_bound=False):
            return False
    return True


async def _record_denial(
    db: AsyncSession,
    user: User,
    request: Request,
    action: str,
    resource_type: str,
    resource_id: str | None,
) -> None:
    """Write a `denied` audit row. Best-effort — never raises."""
    try:
        db.add(
            AuditLog(
                user_id=user.id,
                user_display_name=user.display_name,
                auth_source=getattr(user, "auth_source", "local") or "local",
                source_ip=get_trusted_client_ip(request),
                user_agent=clean_user_agent(request.headers.get("user-agent")),
                action=action,
                resource_type=resource_type,
                resource_id=resource_id or "",
                resource_display=f"{resource_type}:{resource_id or '*'}",
                result="denied",
                error_detail=f"permission denied ({action} on {resource_type})",
            )
        )
        await db.commit()
    except Exception as exc:  # noqa: BLE001 — don't let audit failures block the 403
        logger.warning("permission_audit_write_failed", error=str(exc))


async def refuse_and_audit(
    db: AsyncSession,
    user: User,
    request: Request | None,
    *,
    action: str,
    resource_type: str,
    resource_id: str,
    resource_display: str,
    reason: str,
    status_code: int = status.HTTP_403_FORBIDDEN,
    detail: str,
) -> NoReturn:
    """Write a ``denied`` audit row for a refused mutation, then raise.

    For refusals decided inside a handler (a privilege ceiling, an invariant)
    rather than by a :func:`require_permission` gate, so they leave the same
    trail. Call it before anything is written: the row is committed, and so
    would be any pending change. Best-effort on the audit write, as
    :func:`_record_denial` is — the refusal never depends on it.
    """
    try:
        db.add(
            AuditLog(
                user_id=user.id,
                user_display_name=user.display_name,
                auth_source=getattr(user, "auth_source", "local") or "local",
                source_ip=get_trusted_client_ip(request) if request is not None else None,
                user_agent=(
                    clean_user_agent(request.headers.get("user-agent"))
                    if request is not None
                    else None
                ),
                action=action,
                resource_type=resource_type,
                resource_id=resource_id,
                resource_display=resource_display,
                result="denied",
                error_detail=reason,
            )
        )
        await db.commit()
    except Exception as exc:  # noqa: BLE001 — don't let audit failures block the refusal
        logger.warning("permission_audit_write_failed", error=str(exc))
    raise HTTPException(status_code=status_code, detail=detail)


def require_permission(
    action: str,
    resource_type: str,
) -> Callable[..., Awaitable[User]]:
    """Return a FastAPI dependency that enforces a coarse-grained permission.

    Usage::

        @router.post("/spaces", dependencies=[Depends(require_permission("write", "ip_space"))])

    On denial it writes a `denied` audit row and raises 403. Superadmin always
    passes.
    """

    async def _dep(
        request: Request,
        current_user: CurrentUser,
        db: Annotated[AsyncSession, Depends(get_db)],
    ) -> User:
        if user_has_permission(current_user, action, resource_type):
            return current_user
        await _record_denial(db, current_user, request, action, resource_type, None)
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Permission denied: need '{action}' on '{resource_type}'",
        )

    _dep.spatium_requires = ("exact", [(action, resource_type)])  # type: ignore[attr-defined]
    return _dep


def require_any_permission(*pairs: tuple[str, str]) -> Callable[..., Awaitable[User]]:
    """Dependency that passes if the caller has ANY of (action, resource_type) pairs.

    Useful for endpoints that expose data drawn from multiple resource types
    (e.g. cross-module search).
    """

    async def _dep(
        request: Request,
        current_user: CurrentUser,
        db: Annotated[AsyncSession, Depends(get_db)],
    ) -> User:
        for action, resource_type in pairs:
            if user_has_permission(current_user, action, resource_type):
                return current_user
        # Denied — log against the first pair for traceability.
        action, resource_type = pairs[0] if pairs else ("read", "*")
        await _record_denial(db, current_user, request, action, resource_type, None)
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Permission denied",
        )

    _dep.spatium_requires = ("exact", list(pairs))  # type: ignore[attr-defined]
    return _dep


# ── Router-level method → action mapper ────────────────────────────────────────
#
# Many routers have dozens of endpoints where the HTTP method already tells us
# the action (GET=read, POST/PUT/PATCH=write, DELETE=delete). Hand-annotating
# every endpoint with `dependencies=[Depends(require_permission(...))]` is
# noisy; instead we attach a single dependency at the router level that picks
# the action off the request method.


_METHOD_TO_ACTION = {
    "GET": "read",
    "HEAD": "read",
    "OPTIONS": "read",
    "POST": "write",
    "PUT": "write",
    "PATCH": "write",
    "DELETE": "delete",
}

# POST routes that remove many rows at once. Each removes rows exactly as the
# single-row ``DELETE`` does, so the router-level gates require ``delete`` for
# them, not the ``write`` a POST otherwise implies. Matched as a suffix of the
# request path (the route's last segments are literals, so no path parameter
# can make a request match one of these without being that route).
# ``tests/test_bulk_delete_requires_delete_action.py`` fails on a POST route
# named like a multi-row delete that this list does not cover.
MULTI_ROW_DELETE_SUFFIXES: tuple[str, ...] = (
    "/bulk-delete",
    # ``POST /ipam/subnets/{id}/orphans/purge`` permanently deletes the given
    # orphaned addresses, as ``DELETE /ipam/addresses/{id}?permanent=true``.
    "/orphans/purge",
)


def action_for_request(request: Request) -> str:
    """Return the action a router-level gate requires for ``request``.

    The HTTP method decides, except that a multi-row delete (a POST whose path
    ends in one of :data:`MULTI_ROW_DELETE_SUFFIXES`) needs the same ``delete``
    action as deleting one row.
    """
    method = request.method.upper()
    if method == "POST" and request.url.path.rstrip("/").endswith(MULTI_ROW_DELETE_SUFFIXES):
        return "delete"
    return _METHOD_TO_ACTION.get(method, "write")


def require_resource_permission(resource_type: str) -> Callable[..., Awaitable[User]]:
    """Router-level dependency that enforces permissions by HTTP method.

    The mapping is: GET/HEAD/OPTIONS → ``read``, POST/PUT/PATCH → ``write``,
    DELETE → ``delete``, and a multi-row delete POST → ``delete`` (see
    :func:`action_for_request`). Attach at the router scope::

        router = APIRouter(dependencies=[Depends(require_resource_permission("ip_space"))])

    Per-row checks should still be performed inside handlers that know the
    resource UUID, using :func:`user_has_permission`.
    """

    async def _dep(
        request: Request,
        current_user: CurrentUser,
        db: Annotated[AsyncSession, Depends(get_db)],
    ) -> User:
        action = action_for_request(request)
        if user_has_permission(current_user, action, resource_type):
            return current_user
        await _record_denial(db, current_user, request, action, resource_type, None)
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Permission denied: need '{action}' on '{resource_type}'",
        )

    _dep.spatium_requires = ("method", [resource_type])  # type: ignore[attr-defined]
    return _dep


def require_any_resource_permission(
    *resource_types: str,
) -> Callable[..., Awaitable[User]]:
    """Like :func:`require_resource_permission` but accepts multiple resource types.

    Passes if the user has the method-derived action on ANY of the listed
    resource types. Used by aggregate routers (e.g. IPAM has ip_space, ip_block,
    subnet, ip_address routes all under a single APIRouter, so we accept any of
    those four).
    """

    async def _dep(
        request: Request,
        current_user: CurrentUser,
        db: Annotated[AsyncSession, Depends(get_db)],
    ) -> User:
        action = action_for_request(request)
        for rt in resource_types:
            if user_has_permission(current_user, action, rt):
                return current_user
        first = resource_types[0] if resource_types else "*"
        await _record_denial(db, current_user, request, action, first, None)
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Permission denied: need '{action}' on one of {list(resource_types)}",
        )

    _dep.spatium_requires = ("method", list(resource_types))  # type: ignore[attr-defined]
    return _dep


def has_any_grant_for(user: User, action: str, resource_type: str) -> bool:
    """True if the user holds ANY grant matching ``(action, resource_type)``,
    SCOPED OR UNSCOPED — ``resource_id`` is ignored.

    For COARSE router gates that must admit an instance-scoped delegate so a
    downstream per-row gate can enforce the real boundary. The ordinary
    ``require_*_resource_permission`` dependencies do an *unscoped* check
    (``resource_id=None``) which a purely instance-scoped grant fails:
    ``_resource_id_matches`` returns ``False`` when the request is unscoped but
    the grant is scoped. Address-set delegation (issue #103) hands out scoped
    ``{write, address_set, <id>}`` grants, so the IPAM router gate uses this to
    let those callers *reach* the per-IP gate
    (``app.services.ipam.address_set_gate``), which is the authoritative check.
    """
    if not user.is_active:
        return False
    if is_effective_superadmin(user):
        return True
    perms: list[object] = []
    for group in user.groups:
        for role in group.roles:
            perms.extend(role.permissions or [])
    perms.extend(getattr(user, "_active_time_bound_grants", None) or [])
    for perm in perms:
        triple = _perm_triple(perm)
        if triple is None:
            continue
        g_action, g_type, _rid = triple
        if _action_matches(g_action, action) and _resource_type_matches(g_type, resource_type):
            return True
    return False


def require_any_resource_or_scoped(
    unscoped_types: tuple[str, ...],
    scoped_types: tuple[str, ...],
) -> Callable[..., Awaitable[User]]:
    """Coarse router gate that also admits instance-scoped delegates.

    Passes if the user has the method-derived action (unscoped) on ANY
    ``unscoped_types`` — the normal :func:`require_any_resource_permission`
    behaviour — OR, for **mutating** methods only (write / delete, never read),
    holds ANY grant (scoped or unscoped) on ANY ``scoped_types`` via
    :func:`has_any_grant_for`.

    The scoped admit exists for delegation types (``address_set``, #103) whose
    real boundary is enforced by a downstream per-row gate, so a delegate with
    only ``{write, address_set, <id>}`` clears the coarse gate and reaches that
    gate. It is restricted to write/delete so a scoped *read* grant can never
    widen read access to the aggregate router's data; read still requires a
    normal (typically type-level) read grant.
    """

    async def _dep(
        request: Request,
        current_user: CurrentUser,
        db: Annotated[AsyncSession, Depends(get_db)],
    ) -> User:
        action = action_for_request(request)
        for rt in unscoped_types:
            if user_has_permission(current_user, action, rt):
                return current_user
        if action != "read":
            for rt in scoped_types:
                if has_any_grant_for(current_user, action, rt):
                    return current_user
        all_types = list(unscoped_types) + list(scoped_types)
        first = all_types[0] if all_types else "*"
        await _record_denial(db, current_user, request, action, first, None)
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Permission denied: need '{action}' on one of {all_types}",
        )

    _dep.spatium_requires = ("method", list(unscoped_types))  # type: ignore[attr-defined]
    return _dep


# ── Known synthetic permission resource_types ─────────────────────────────────
#
# Most resource_types map 1:1 to a real DB row (``ip_space``, ``dns_zone`` …),
# but a handful of admin-only surfaces use synthetic ``manage_*`` scopes that
# guard a feature rather than a row. Centralising the list here keeps the
# `_BUILTIN_ROLES` seed in `app.main` and the documentation in
# `docs/PERMISSIONS.md` honest as new ones land.
KNOWN_MANAGE_PERMISSIONS: frozenset[str] = frozenset(
    {
        "manage_block_sync",
        "manage_dns_pools",
        "manage_domains",
        "manage_firewall_enforcement",
        "manage_network_devices",
        "manage_nmap_scans",
        "manage_packet_capture",
    }
)


__all__ = [
    "action_for_request",
    "KNOWN_MANAGE_PERMISSIONS",
    "MULTI_ROW_DELETE_SUFFIXES",
    "caller_can_grant",
    "effective_grants",
    "is_effective_superadmin",
    "require_any_permission",
    "require_any_resource_permission",
    "require_permission",
    "require_resource_permission",
    "token_scope_allows",
    "token_scoped_resource_ids",
    "user_has_permission",
]
