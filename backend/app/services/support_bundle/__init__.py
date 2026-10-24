"""Platform-wide support bundle (issue #875).

Builds a zip an operator can attach to a **public** GitHub issue.
Attachments there are effectively world-readable, so the bundle is
scrubbed by default and the unscrubbed variant is a deliberate,
differently-named opt-in for local debugging.

Three-step flow rather than one download, because proposal 3 of the
issue asks for a self-review step and it is the right shape anyway:

1. :func:`generate` builds the archive and a preview (file list, sizes,
   what the scrubber replaced, a redacted sample).
2. The operator reads the preview and downloads the archive.
3. If support later says "n123.d456.invalid is unhealthy", the decode
   map answers which host that is.

The decode map is returned by a **separate** call and never written into
the archive. A bundle carrying its own decoder is not scrubbed, it is
merely inconvenient to read.

Assembly is in memory. A zip's central directory is written last, so
true streaming needs a third-party writer, and the honest alternative is
a hard cap — :data:`~.collect.CAP_TOTAL_BYTES` — that bounds peak RSS
instead of pretending the problem away.
"""

from __future__ import annotations

import io
import json
import uuid
import zipfile
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import structlog
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.core.versions import canonical_version
from app.services.support_bundle import collect
from app.services.support_bundle.scrub import Scrubber, safety_net

logger = structlog.get_logger(__name__)

__all__ = ["BundleResult", "FilePreview", "generate"]


@dataclass
class FilePreview:
    path: str
    bytes: int
    truncated: bool


@dataclass
class BundleResult:
    id: str
    filename: str
    archive: bytes
    files: list[FilePreview]
    manifest: dict[str, Any]
    decode_map: dict[str, dict[str, str]]
    scrubbed: bool
    # Sections that raised. Present in the manifest so a reader can tell
    # "this install has no DNS servers" from "the DNS collector broke".
    errors: list[str] = field(default_factory=list)
    sample: str = ""


async def _safe(
    name: str,
    factory: Callable[[], Any],
    errors: list[str],
    db: AsyncSession | None = None,
) -> Any:
    """Run one collector, converting a failure into an in-bundle note.

    A bundle is requested when something is already broken, and the
    sections most likely to raise describe exactly that breakage. A 500
    here would deny the operator the diagnostics *because* the system
    needs diagnosing.

    Each DB-touching collector runs inside a SAVEPOINT. Without one, a
    single failed statement puts PostgreSQL into "current transaction is
    aborted, commands ignored until end of transaction block" and every
    *later* collector fails too — so one missing table would turn into
    an almost-empty bundle whose section_errors all blame the wrong
    thing. Rolling back to the savepoint confines the damage to the
    section that caused it.

    ``factory`` is a callable rather than an already-created coroutine
    because the savepoint has to open *before* the query is issued.
    """
    try:
        if db is not None:
            async with db.begin_nested():
                result = factory()
                return await result if hasattr(result, "__await__") else result
        result = factory()
        return await result if hasattr(result, "__await__") else result
    except Exception as exc:  # noqa: BLE001 — recorded, never raised
        logger.warning("support_bundle_section_failed", section=name, error=str(exc))
        errors.append(f"{name}: {type(exc).__name__}: {exc}")
        return f"[section failed: {type(exc).__name__}: {exc}]"


def _merge(sections: dict[str, str], prefix: str, produced: Any) -> None:
    """Fold a multi-file collector's output into ``sections``.

    ``_safe`` reports a failure by RETURNING a note string, not by
    raising — so a caller that assumed a dict and went straight for
    ``.items()`` got an ``AttributeError`` out of the one code path whose
    entire purpose is that a broken collector cannot 500 the bundle.
    A non-dict result is filed as the section's own note instead.
    """
    if isinstance(produced, dict):
        for name, body in produced.items():
            sections[f"{prefix}/{name}"] = body
        return
    sections[f"{prefix}/_error.txt"] = str(produced or "")


async def generate(db: AsyncSession, *, scrubbed: bool = True) -> BundleResult:
    """Assemble the bundle.

    ``scrubbed=False`` keeps real hostnames and addresses for an operator
    debugging their own install. It does NOT keep secrets: those are
    hard-excluded in every mode, because there is no version of "let me
    read my own logs" that is improved by including the key which
    decrypts the database.
    """
    scrub = Scrubber(enabled=scrubbed)
    errors: list[str] = []
    sections: dict[str, str] = {}

    # ── DB-backed ───────────────────────────────────────────────────
    sections["versions.json"] = await _safe(
        "versions", lambda: collect.collect_versions(db), errors, db
    )
    sections["health/self-test.txt"] = await _safe(
        "self_test", lambda: collect.collect_self_test(scrub), errors
    )
    sections["health/db-connections.json"] = await _safe(
        "db_pool", lambda: collect.collect_db_pool(db), errors, db
    )
    sections["health/table-sizes.json"] = await _safe(
        "table_sizes", lambda: collect.collect_table_sizes(db), errors, db
    )
    sections["errors/internal-errors.json"] = await _safe(
        "internal_errors", lambda: collect.collect_internal_errors(db, scrub), errors, db
    )
    sections["alerts/events.json"] = await _safe(
        "alert_events", lambda: collect.collect_alert_events(db, scrub), errors, db
    )
    sections["audit/recent.json"] = await _safe(
        "audit_tail", lambda: collect.collect_audit_tail(db, scrub), errors, db
    )
    sections["activity/recent.log"] = await _safe(
        "recent_app_logs", lambda: collect.collect_recent_app_logs(db, scrub), errors, db
    )
    sections["config/feature-modules.json"] = await _safe(
        "feature_modules", lambda: collect.collect_feature_modules(db), errors, db
    )
    sections["config/platform-settings.json"] = await _safe(
        "platform_settings", lambda: collect.collect_platform_settings(db, scrub), errors, db
    )
    sections["config/integrations.json"] = await _safe(
        "integrations", lambda: collect.collect_integration_state(db), errors, db
    )
    sections["agents/servers.json"] = await _safe(
        "agent_state", lambda: collect.collect_agent_state(db, scrub), errors, db
    )

    # ── Host / runtime ──────────────────────────────────────────────
    sections["system/env.txt"] = await _safe(
        "environment", lambda: collect.collect_environment(scrub), errors
    )
    _merge(sections, "system", await _safe("proc", lambda: collect.collect_proc(scrub), errors))
    _merge(
        sections,
        "containers",
        await _safe("pods", lambda: collect.collect_container_logs(scrub), errors),
    )
    _merge(
        sections, "logs", await _safe("host_logs", lambda: collect.collect_host_logs(scrub), errors)
    )

    # ── Safety net ──────────────────────────────────────────────────
    #
    # Every collector is supposed to redact its own secrets. This runs
    # over the assembled text anyway: "a collector forgot" and "a new
    # settings column appeared" are ordinary events, and the consequence
    # — a credential on a public issue — cannot be taken back.
    for path in list(sections):
        value = sections[path]
        if isinstance(value, str):
            sections[path] = safety_net(path, value, scrub.report)

    # ── Manifest ────────────────────────────────────────────────────
    bundle_id = str(uuid.uuid4())
    stamp = datetime.now(tz=UTC)
    manifest: dict[str, Any] = {
        "bundle_id": bundle_id,
        "generated_at": stamp.isoformat(),
        "product_version": canonical_version(settings.version, settings.app_version),
        "appliance_mode": settings.appliance_mode,
        "scrubbed": scrubbed,
        "scrub": {
            "ipv4_mapped": scrub.report.ips_v4,
            "ipv6_mapped": scrub.report.ips_v6,
            "macs_mapped": scrub.report.macs,
            "hostnames_mapped": scrub.report.hostnames,
            "usernames_mapped": scrub.report.usernames,
            "secrets_redacted": scrub.report.secrets_redacted,
            # A non-empty list means a collector shipped something it
            # should have redacted itself. The net caught it, and saying
            # so is how the underlying bug gets fixed instead of living
            # behind a net that may not catch the next variant.
            "safety_net_hits": scrub.report.safety_net_hits,
        },
        "section_errors": errors,
        "READ_THIS": (
            "Attachments on a PUBLIC GitHub issue are readable by anyone who "
            "can see the issue, and deleting the comment does not reliably "
            "remove the file. Scrubbing here is best-effort, the same caveat "
            "sos report --clean carries: freeform text can hold an identifier "
            "in a shape no pattern anticipates. REVIEW THIS ARCHIVE BEFORE "
            "SHARING IT."
            if scrubbed
            else "*** THIS BUNDLE IS NOT SCRUBBED. *** It contains real "
            "hostnames, IP addresses, MAC addresses and usernames. It is for "
            "local debugging only — do NOT attach it to a public issue. "
            "(Credentials are still excluded: those are never included in any "
            "mode.)"
        ),
    }

    # ── Assemble ────────────────────────────────────────────────────
    buf = io.BytesIO()
    files: list[FilePreview] = []
    total = 0
    skipped_for_size: list[str] = []
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for path in sorted(sections):
            body = sections[path] or ""
            encoded = body.encode("utf-8", errors="replace")
            if total + len(encoded) > collect.CAP_TOTAL_BYTES:
                skipped_for_size.append(path)
                continue
            total += len(encoded)
            zf.writestr(path, body)
            files.append(
                FilePreview(
                    path=path,
                    bytes=len(encoded),
                    truncated=collect.TRUNCATION_MARKER in body,
                )
            )
        if skipped_for_size:
            manifest["sections_omitted_for_size"] = skipped_for_size
        # Written last so it reflects the omissions above.
        zf.writestr("manifest.json", json.dumps(manifest, indent=2, default=str))

    kind = "" if scrubbed else "UNSCRUBBED-"
    filename = f"spatiumddi-support-bundle-{kind}{stamp.strftime('%Y%m%d-%H%M%S')}.zip"

    # A short, redacted excerpt for the review step, so the operator sees
    # what scrubbing actually did before deciding to attach it.
    sample_source = sections.get("activity/recent.log") or sections.get("versions.json") or ""
    sample = "\n".join(sample_source.splitlines()[:20])

    logger.info(
        "support_bundle_generated",
        bundle_id=bundle_id,
        scrubbed=scrubbed,
        files=len(files),
        bytes=buf.tell(),
        section_errors=len(errors),
        safety_net_hits=len(scrub.report.safety_net_hits),
    )

    return BundleResult(
        id=bundle_id,
        filename=filename,
        archive=buf.getvalue(),
        files=files,
        manifest=manifest,
        decode_map=scrub.decode_map(),
        scrubbed=scrubbed,
        errors=errors,
        sample=sample,
    )
