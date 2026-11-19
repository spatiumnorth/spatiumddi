"""One resolver for the desired slot-image state an appliance is told to fetch.

Two surfaces schedule OS slot upgrades — the per-box Fleet action
(``schedule_appliance_upgrade``) and the multi-node rolling orchestrator
(``/api/v1/upgrades/{run}/start`` → ``_step_trigger_slot_apply``). Both
must stamp the SAME four ``Appliance.desired_slot_image_*`` columns,
because the supervisor writes all four into the host trigger file and the
host runner needs every one of them to fetch successfully.

They diverged: the orchestrator stamped only version + URL, leaving
``desired_slot_image_sha256`` and ``desired_slot_image_tls_insecure``
unset. For an uploaded image that means the host fetches the appliance's
own self-signed HTTPS URL with cert verification ON and no hash to verify
against — exactly the #386 failure, re-introduced on the rolling path
(#787). Worse, a stale sha256 left on the row from an earlier per-box
schedule would be checked against the new image and fail as corruption.

So resolution and stamping live here, and both callers go through them.
Adding a fifth field means touching one function, not remembering two.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.versions import includes_release
from app.models.appliance import Appliance, ApplianceUpgradeImage
from app.services.appliance.architecture import architecture_conflict

# The host runner only learned to strip a URL ``#fragment`` before
# fetching in #386, first released in 2026.06.12-2 (2026.06.12-1 was
# tagged before it merged). An older runner passes the fragment straight
# to the downloader and the apply wedges at "in-flight" forever (#419),
# so the nonce is gated on the appliance's version.
URL_FRAGMENT_STRIP_MIN_VERSION = "2026.06.12-2"


class SlotImageResolutionError(Exception):
    """The requested upgrade image could not be resolved to a fetchable target."""


class SlotImageArchitectureMismatch(SlotImageResolutionError):
    """The image and the node are built for different architectures (#1026).

    A SUBCLASS of the resolution error on purpose: both API surfaces that
    schedule an upgrade already map ``SlotImageResolutionError`` to a
    422, so the refusal reaches the operator as a 422 with this message
    without either handler having to learn a new exception. The
    orchestrator, which stamps without resolving, catches it explicitly.
    """


@dataclass(frozen=True)
class SlotImageTarget:
    """Everything the host needs to fetch + verify one slot image.

    ``sha256`` and ``tls_insecure`` are meaningful only for an image we
    serve ourselves: we know its hash, and we know the URL points at our
    own self-signed web cert. An operator-pasted external URL is fetched
    over public-CA TLS with no hash (the ``.xz`` container's own integrity
    check is what catches a truncated or corrupted download there).
    """

    url: str
    sha256: str | None = None
    tls_insecure: bool = False
    # #1026 — the architecture the image's rootfs is built for, when we
    # know it: an uploaded/imported row carries one, an operator-pasted
    # external URL never can. None is UNKNOWN and never blocks — the
    # host runner re-checks the real bytes before writing them.
    architecture: str | None = None
    # #386 Part B re-fire nonce, appended to the URL as ``#a=<nonce>`` so a
    # fresh apply of the same image is a distinct desired-state and the
    # supervisor's fire-once marker doesn't suppress it. It lives on the
    # TARGET, not minted per stamp, because the rolling orchestrator
    # re-drives an incomplete node from step 1 on resume: a nonce minted
    # per call would hand that node a URL it has never fired and trigger a
    # second full slot apply of an image it already staged. Carried in the
    # run plan so every node in a run, and every resume of it, agrees.
    nonce: str | None = None
    # #1709 — the uploaded image this URL serves, when it is one of ours. An
    # upload streams its bytes to the slot-image mirror, so the mirror
    # headroom check needs no room for it once the mirror holds it. None for
    # an operator-pasted external URL.
    image_id: uuid.UUID | None = None

    def as_plan_fields(self) -> dict[str, object]:
        """Serialise into an ``UpgradeRun.plan`` JSON blob."""
        return {
            "slot_image_url": self.url,
            "slot_image_sha256": self.sha256,
            "slot_image_tls_insecure": self.tls_insecure,
            "slot_image_nonce": self.nonce,
            "slot_image_architecture": self.architecture,
            "slot_image_id": str(self.image_id) if self.image_id else None,
        }

    @classmethod
    def from_plan_fields(cls, plan: dict) -> SlotImageTarget:
        """Rebuild from an ``UpgradeRun.plan`` blob.

        Tolerates a plan written before the two integrity fields existed —
        those runs resolve to the same (url-only) target they had then.
        """
        return cls(
            url=plan.get("slot_image_url") or "",
            sha256=plan.get("slot_image_sha256"),
            tls_insecure=bool(plan.get("slot_image_tls_insecure", False)),
            nonce=plan.get("slot_image_nonce"),
            # Absent in a plan written before #1026 — those runs resolve
            # to UNKNOWN and fall through to the host runner's check,
            # which is the same answer they had when they were planned.
            architecture=plan.get("slot_image_architecture"),
            # Absent in a plan written before #1709: the check then asks for
            # room as it did when the run was planned.
            image_id=_uuid_or_none(plan.get("slot_image_id")),
        )


# #1752 — the schemes the supervisor will fetch a slot image over. MUST match
# ``allowed_schemes`` in ``agent/supervisor/spatium_supervisor/appliance_state.py``
# (#242: no cleartext ``http://`` OS-image fetch); a drift test pins the two.
# The supervisor refuses anything else silently (a warning log, no trigger),
# so a URL outside this set makes a rolling upgrade wait out its whole stage
# timeout per node. Every operator-supplied slot image URL is checked here
# (the Plan validator and ``resolve_slot_image_target``). An uploaded image's
# URL is composed from the address the UI was reached on, which on an
# appliance is the frontend's https:// listener.
SUPERVISOR_ALLOWED_URL_SCHEMES: tuple[str, ...] = ("https", "file")


def slot_image_url_problem(url: str) -> str | None:
    """Why the supervisor would refuse ``url``, or None when it would accept it.

    Mirrors the supervisor's own test exactly: the stripped, fragment-less URL
    must START with ``https://`` or ``file://`` (case-insensitive). A parse of
    the scheme is not the same test — ``file:/x`` parses as scheme ``file``
    and the supervisor still refuses it.
    """
    fetch_url = url.strip().split("#", 1)[0]
    lowered = fetch_url.lower()
    if not any(lowered.startswith(f"{s}://") for s in SUPERVISOR_ALLOWED_URL_SCHEMES):
        allowed = " or ".join(f"{x}://" for x in SUPERVISOR_ALLOWED_URL_SCHEMES)
        got = fetch_url.split(":", 1)[0][:32] if ":" in fetch_url else ""
        return (
            f"slot image URL must start with {allowed} (got {got + ':' if got else 'no scheme'}): "
            "appliances refuse any other OS-image fetch, including cleartext http://, "
            "so the upgrade would wait for a download that never starts"
        )
    if lowered.startswith("https://"):
        from urllib.parse import urlsplit  # noqa: PLC0415

        try:
            host = urlsplit(fetch_url).hostname
        except ValueError as exc:
            return f"slot image URL is not parseable: {exc}"
        if not host:
            return "slot image URL must include a host"
    return None


def _uuid_or_none(value: object) -> uuid.UUID | None:
    try:
        return uuid.UUID(str(value)) if value else None
    except ValueError:
        return None


def supervisor_strips_url_fragment(row: Appliance) -> bool:
    """True if this appliance's runner strips a URL ``#fragment`` (≥ #386).

    The runner that strips it is ``spatiumddi-slot-upgrade``, which ships
    in the slot OS, so the installed appliance version decides. The
    supervisor's own version is the fallback for a row that has not
    reported one. Until #1183 the supervisor always reported the frozen
    ``2026.05.14.1``, and reading it first sent every appliance down the
    clean-URL path.

    A dev build, a nightly cut on the release's own date, or no version at
    all stays on the safe clean-URL path. That loses only the re-fire of
    the *same* image (a new version already changes the URL), never the
    ability to upgrade (#419).
    """
    for version in (row.installed_appliance_version, row.supervisor_version):
        verdict = includes_release(version, URL_FRAGMENT_STRIP_MIN_VERSION)
        if verdict is not None:
            return verdict
    return False


async def resolve_slot_image_target(
    db: AsyncSession,
    *,
    base_url: str,
    slot_image_id: uuid.UUID | None = None,
    slot_image_url: str | None = None,
) -> SlotImageTarget:
    """Resolve an upload-or-URL choice into a fetchable target.

    Exactly one of ``slot_image_id`` / ``slot_image_url`` must be given;
    callers validate that at the request-model layer and this asserts it.

    For an uploaded image the URL is composed against ``base_url`` — the
    operator-facing scheme + host the frontend reached us on, which is
    also the address the supervisor already heartbeats to. The ``?t=``
    HMAC authorises the host runner's unauthenticated GET; it is bound to
    the image id, so a leaked URL cannot be replayed for another image.

    Raises ``SlotImageResolutionError`` when the image row is missing.
    """
    if (slot_image_id is None) == (slot_image_url is None):
        raise SlotImageResolutionError("Pass exactly one of slot_image_id or slot_image_url.")

    if slot_image_url is not None:
        problem = slot_image_url_problem(slot_image_url)
        if problem:
            raise SlotImageResolutionError(problem)
        return SlotImageTarget(url=slot_image_url)

    assert slot_image_id is not None  # narrowed by the check above
    # #2400 — held until the caller's transaction ends, so the reclaim sweep
    # (and the delete endpoint) cannot remove the image between here and
    # the schedule this resolves into being committed.
    from app.services.appliance.upgrade_image_catalog import (  # noqa: PLC0415
        lock_catalog_shared,
    )

    await lock_catalog_shared(db)
    image = await db.get(ApplianceUpgradeImage, slot_image_id)
    if image is None:
        raise SlotImageResolutionError(f"Upgrade image {slot_image_id} not found.")

    # Imported locally: the token mint lives on the API router that also
    # serves the bytes, and importing it at module scope would cycle back
    # through the router package.
    from app.api.v1.appliance.upgrade_images import (  # noqa: PLC0415
        slot_image_download_token,
    )

    token = slot_image_download_token(image.id)
    return SlotImageTarget(
        url=(
            f"{base_url.rstrip('/')}"
            f"/api/v1/appliance/upgrade-images/{image.id}/raw.xz?t={token}"
        ),
        sha256=image.sha256,
        tls_insecure=True,
        architecture=image.architecture,
        image_id=image.id,
    )


def new_refire_nonce() -> str:
    """Mint one ``#a=`` re-fire nonce. Call once per scheduling decision."""
    return uuid.uuid4().hex[:12]


def desired_slot_image_url(row: Appliance, target: SlotImageTarget) -> str:
    """The URL ``stamp_desired_slot_image`` writes onto ``row`` for ``target``.

    The target's URL, with the re-fire nonce appended when the appliance's
    runner is known to strip the fragment (#419). When it equals the row's
    current ``desired_slot_image_url`` the stamp repeats the node's last
    request, which the supervisor's fire-once marker does not act on again.
    """
    if target.nonce and supervisor_strips_url_fragment(row):
        return f"{target.url}#a={target.nonce}"
    return target.url


def stamp_desired_slot_image(
    row: Appliance,
    target: SlotImageTarget,
    *,
    desired_version: str,
) -> None:
    """Write all four desired-state columns onto ``row``.

    The re-fire nonce comes from ``target``, so re-stamping the same target
    (an orchestrator resume re-driving a node) reproduces the identical URL
    and the supervisor's fire-once marker still suppresses it. Appended
    only when the appliance's runner is known to strip the fragment (#419).

    Raises ``SlotImageArchitectureMismatch`` when the image and the node
    are known to be built for different architectures (#1026) — nothing
    is written to ``row`` in that case.
    """
    url = desired_slot_image_url(row, target)

    if architecture_conflict(target.architecture, row.architecture):
        # #1026. The download would verify (the SHA matches — it is a
        # perfectly good image), the slot would be written, GRUB would
        # switch, and the node would not come back. Nothing downstream
        # of here can tell the difference, so the refusal belongs at the
        # moment the desired state is written.
        #
        # It lives in ``stamp`` rather than in each caller for the reason
        # this module exists at all: three surfaces write these columns,
        # and a check remembered in two of them is a check the third one
        # skips.
        raise SlotImageArchitectureMismatch(
            f"Upgrade image is {target.architecture}, but "
            f"{row.hostname or 'this appliance'} is {row.architecture}. "
            "Applying it would write a rootfs the node cannot boot."
        )

    row.desired_appliance_version = desired_version
    row.desired_slot_image_url = url
    row.desired_slot_image_sha256 = target.sha256
    row.desired_slot_image_tls_insecure = target.tls_insecure


__all__ = [
    "URL_FRAGMENT_STRIP_MIN_VERSION",
    "SlotImageArchitectureMismatch",
    "SlotImageResolutionError",
    "SlotImageTarget",
    "desired_slot_image_url",
    "new_refire_nonce",
    "resolve_slot_image_target",
    "stamp_desired_slot_image",
    "supervisor_strips_url_fragment",
]
