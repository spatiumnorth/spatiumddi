"""Can an older release run on this database? (#1227)

PostgreSQL lives on ``/var``, which survives an A/B slot swap. Going back to
an older release (a slot rollback, a Fleet ``set-next-boot`` /
``set-default-slot`` onto the previous slot, or a per-box "upgrade" to an
older image) therefore puts that release's code on a database the newer
release has already migrated forward. Alembic cannot migrate backwards from a
revision it has never heard of, so the older release's migrate step fails with
``Can't locate revision``, its api / worker / beat wait on migrate forever,
and nothing retries. On a single node the newer release's api even keeps
serving behind the older UI, because the older pods never become ready.

:func:`check_release_can_run` answers the question before the switch, from
the one side that CAN answer it: the newer release, which holds the whole
migration tree. What it needs is the head the target release was built with,
from two sources:

* ``app/data/release_schema_heads.json`` — generated from the release tags
  (``scripts/release_schema_heads.py``). It is built from the tags
  themselves, so for a release it lists it is the truth and wins;
* ``release_schema_head`` — every release records itself at startup
  (:func:`record_running_release`), so the release an appliance upgraded
  FROM is there even when it is a nightly or dev build no tag names.

A recorded row is only as true as the process that wrote it. After a
rollback to a release that cannot migrate, the newer release's api keeps
running on the older slot, and it must not record the booted slot's version
against its own head: that row would turn the next rollback to the older
release into a pass (#1300 QA walk). So a process records the booted slot
only when that slot is its own release.

The verdict is one of three, and ``unknown`` is never read as either of the
others: a nightly that predates the table, or a slot whose version was never
reported, cannot be judged, and refusing on "do not know" would block every
rollback on an install that has never recorded anything. Only
``incompatible`` refuses, and the operator can still proceed with an explicit
acknowledgement, because rolling back and then restoring a pre-upgrade copy of
the database by hand is a legitimate plan.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import asdict, dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any, Literal

import structlog
from fastapi import HTTPException, status
from sqlalchemy import func, text
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.versions import nightly_build_date
from app.models.release_schema import ReleaseSchemaHead

logger = structlog.get_logger(__name__)

Verdict = Literal["compatible", "incompatible", "unknown"]
HeadSource = Literal["recorded", "bundled"]

_BUNDLED = Path(__file__).resolve().parent.parent.parent / "data" / "release_schema_heads.json"

#: The ``detail.code`` of the 409. The Fleet UI keys its confirmation on it,
#: so it is a contract, not a message.
REFUSAL_CODE = "schema_rollback_unsafe"

# Version strings that name no particular build, so recording them would
# teach the table a head that the next build under the same name contradicts.
_UNNAMED_VERSIONS = frozenset({"", "dev", "latest", "unknown"})


@dataclass(frozen=True)
class SchemaRollbackCheck:
    verdict: Verdict
    target_version: str | None
    target_head: str | None
    head_source: HeadSource | None
    database_revision: str | None
    message: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@lru_cache(maxsize=1)
def _bundled_heads() -> dict[str, str]:
    try:
        data = json.loads(_BUNDLED.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning("release_schema_heads_unreadable", path=str(_BUNDLED), error=str(exc))
        return {}
    releases = data.get("releases") if isinstance(data, dict) else None
    if not isinstance(releases, dict):
        return {}
    return {str(k): str(v) for k, v in releases.items() if isinstance(v, str)}


@lru_cache(maxsize=1)
def _script_directory() -> Any:
    """This release's migration tree, or None when it cannot be read."""
    from alembic.config import Config  # noqa: PLC0415
    from alembic.script import ScriptDirectory  # noqa: PLC0415

    from app.core.schema_check import _locate_alembic_ini  # noqa: PLC0415

    ini = _locate_alembic_ini()
    if ini is None:
        return None
    return ScriptDirectory.from_config(Config(str(ini)))


def _in_tree(script: Any, revision: str) -> bool:
    try:
        return script.get_revision(revision) is not None
    except Exception:  # noqa: BLE001 — unknown / malformed id is "not in the tree"
        return False


def _descends_from(script: Any, descendant: str, ancestor: str) -> bool:
    """True when ``ancestor`` lies on ``descendant``'s chain back to base."""
    if descendant == ancestor:
        return True
    return any(rev.revision == ancestor for rev in script.iterate_revisions(descendant, "base"))


def judge(
    *,
    target_version: str | None,
    target_head: str | None,
    head_source: HeadSource | None,
    database_revision: str | None,
    script: Any,
) -> SchemaRollbackCheck:
    """The verdict, from facts already gathered. Pure: no I/O."""

    def result(verdict: Verdict, message: str) -> SchemaRollbackCheck:
        return SchemaRollbackCheck(
            verdict=verdict,
            target_version=target_version,
            target_head=target_head,
            head_source=head_source,
            database_revision=database_revision,
            message=message,
        )

    if not target_version:
        return result("unknown", "the version installed on the target slot is not known")
    if target_head is None:
        return result(
            "unknown",
            f"there is no record of the database schema {target_version} was built with",
        )
    if database_revision is None:
        return result("unknown", "the database's schema revision could not be read")
    if database_revision == target_head:
        return result("compatible", f"the database is at {target_version}'s schema")
    if script is None:
        return result("unknown", "this release's migration tree could not be read")
    if not (_in_tree(script, database_revision) and _in_tree(script, target_head)):
        return result(
            "unknown",
            f"the database revision {database_revision} or {target_version}'s head "
            f"{target_head} is not in this release's migration tree",
        )
    try:
        target_is_ahead = _descends_from(script, target_head, database_revision)
        database_is_ahead = _descends_from(script, database_revision, target_head)
    except Exception as exc:  # noqa: BLE001 — a tree Alembic cannot walk is "unknown"
        return result("unknown", f"the migration tree could not be walked: {exc}")
    if target_is_ahead:
        # The target is ahead of the database: its migrate step moves it
        # forward, which is the ordinary upgrade case.
        return result(
            "compatible",
            f"{target_version} can migrate the database forward from {database_revision}",
        )
    if database_is_ahead:
        return result(
            "incompatible",
            f"The database is at schema revision {database_revision}, which a newer "
            f"release migrated it to. {target_version} was built with {target_head} and "
            "cannot run on it: its migrate step would fail with \"Can't locate "
            'revision", and its api, worker and beat would never start. Stay on this '
            "release, or go back only with a plan to restore a copy of the database "
            f"taken before the upgrade. See 'Rolling back' in docs/deployment/APPLIANCE.md.",
        )
    return result(
        "unknown",
        f"the database revision {database_revision} and {target_version}'s head "
        f"{target_head} are on different branches of the migration tree",
    )


async def _database_revision(db: AsyncSession) -> str | None:
    try:
        rows = (await db.execute(text("SELECT version_num FROM alembic_version"))).all()
    except Exception as exc:  # noqa: BLE001 — surfaces as verdict "unknown"
        logger.warning("schema_rollback_revision_unreadable", error=str(exc))
        return None
    # A branched schema carries one row per head; a single answer is all
    # this check can reason about.
    return rows[0][0] if len(rows) == 1 else None


async def _target_head(db: AsyncSession, version: str) -> tuple[str | None, HeadSource | None]:
    # The bundled table is generated from the release tags, so for a release
    # it lists it cannot be wrong; a recorded row can be (see the module
    # docstring). Recorded rows answer only for builds no tag names.
    bundled = _bundled_heads().get(version)
    if bundled is not None:
        return bundled, "bundled"
    recorded = await db.get(ReleaseSchemaHead, version)
    if recorded is not None:
        return recorded.alembic_head, "recorded"
    return None, None


async def check_release_can_run(
    db: AsyncSession, target_version: str | None
) -> SchemaRollbackCheck:
    """Whether ``target_version`` can start on this database as it is now."""
    target_version = (target_version or "").strip() or None
    head, source = (
        (None, None) if target_version is None else await _target_head(db, target_version)
    )
    try:
        script = _script_directory()
    except Exception as exc:  # noqa: BLE001 — surfaces as verdict "unknown"
        logger.warning("schema_rollback_tree_unreadable", error=str(exc))
        script = None
    check = judge(
        target_version=target_version,
        target_head=head,
        head_source=source,
        database_revision=await _database_revision(db),
        script=script,
    )
    logger.info("schema_rollback_checked", **check.to_dict())
    return check


def enforce(check: SchemaRollbackCheck, *, acknowledged: bool) -> None:
    """Raise the 409 for an ``incompatible`` verdict the caller did not acknowledge."""
    if check.verdict == "incompatible" and not acknowledged:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            {
                "code": REFUSAL_CODE,
                **check.to_dict(),
                "hint": "Resend with acknowledge_schema_rollback=true to proceed anyway.",
            },
        )


async def record_running_release(db: AsyncSession, versions: Iterable[str | None]) -> list[str]:
    """Record that these version strings run at this build's head.

    Only call once the database is AT this build's head: the row is a claim
    that this release can run on that revision, and a behind-schema startup
    would record the wrong one. Returns the versions written.
    """
    from app.core.schema_check import expected_alembic_head  # noqa: PLC0415

    head, err = expected_alembic_head()
    if head is None:
        logger.warning("release_schema_head_not_recorded", reason=err)
        return []
    names = sorted(
        {v.strip() for v in versions if v and v.strip().lower() not in _UNNAMED_VERSIONS}
    )
    for name in names:
        stmt = pg_insert(ReleaseSchemaHead).values(version=name[:64], alembic_head=head)
        await db.execute(
            stmt.on_conflict_do_update(
                index_elements=[ReleaseSchemaHead.version],
                set_={"alembic_head": head, "recorded_at": func.now()},
            )
        )
    await db.commit()
    if names:
        logger.info("release_schema_head_recorded", versions=names, alembic_head=head)
    return names


def _slot_is_this_build(booted: str, version: str | None) -> bool:
    """Whether the booted slot's APPLIANCE_VERSION names the build this process is.

    A release build stamps both from its tag, so they are equal. A nightly
    does not: its images are tagged ``nightly-YYYYMMDD`` (the chart's
    ``image.tag``, hence ``settings.version``) while its slot carries
    ``0.0.0-nightly-YYYYMMDD+<sha>``. Without this pairing a nightly would
    never record its slot, and a rollback to it would always read ``unknown``.
    """
    booted = booted.strip()
    version = (version or "").strip()
    if booted == version:
        return True
    night = nightly_build_date(booted)
    return night is not None and version == f"nightly-{night:%Y%m%d}"


async def record_this_release() -> None:
    """Startup hook: record this build's head under the names it runs as.

    That is the image version and, on an appliance, the booted slot's
    APPLIANCE_VERSION, which is what a rollback looks the slot up by — but
    only when that slot is this build (:func:`_slot_is_this_build`). When it
    is not, this process is the newer release's api still running after a
    rollback to a slot whose own release cannot migrate. Recording the slot
    then would claim that older release runs at this head, and the next
    rollback to it would pass the check.
    """
    from app.config import settings  # noqa: PLC0415
    from app.core.schema_check import schema_at_head  # noqa: PLC0415
    from app.db import AsyncSessionLocal  # noqa: PLC0415
    from app.services.appliance.slot import get_slot_status  # noqa: PLC0415

    at_head = await schema_at_head()
    if not at_head.ok:
        logger.info("release_schema_head_deferred", detail=at_head.detail)
        return
    names: list[str | None] = [settings.version]
    slots = get_slot_status()
    booted = (
        slots.slot_a_version
        if slots.current_slot == "slot_a"
        else slots.slot_b_version if slots.current_slot == "slot_b" else None
    )
    if booted and not _slot_is_this_build(booted, settings.version):
        logger.warning(
            "release_schema_head_slot_not_recorded",
            booted_slot_version=booted,
            this_release=settings.version,
            reason="the booted slot is not this release",
        )
    elif booted:
        names.append(booted)
    async with AsyncSessionLocal() as db:
        await record_running_release(db, names)
