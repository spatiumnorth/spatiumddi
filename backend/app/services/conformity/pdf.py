"""Conformity audit PDF — auditor-facing export.

Generated synchronously by the export endpoint. Reads the latest
``ConformityResult`` per (policy, resource) tuple and renders a
single PDF organised by framework. Each policy section lists pass /
warn / fail / not_applicable counts and enumerates failing rows
with the diagnostic JSON pretty-printed beneath.

PDF integrity hint: a SHA-256 hash of every result row's id+status
is included in the footer so an auditor can detect post-hoc edits.
The hash is over result UUIDs and statuses only — diagnostic blobs
are excluded so a noisy field doesn't change the hash without the
status flipping.
"""

from __future__ import annotations

import asyncio
import hashlib
import io
import json
from collections.abc import Iterable
from datetime import UTC, datetime
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import LETTER
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.conformity import ConformityPolicy, ConformityResult

# ── Aggregation helpers ─────────────────────────────────────────────


async def _latest_results_per_policy(
    db: AsyncSession,
    *,
    policy_ids: Iterable[str] | None = None,
) -> dict[str, list[ConformityResult]]:
    """Return ``{policy_id: [latest result per resource]}``.

    The query pulls every result joined to its policy, then dedupes
    in-Python keeping the newest per ``(policy_id, resource_kind,
    resource_id)``. Avoids a window-function dialect dependency.
    """
    q = select(ConformityResult).order_by(desc(ConformityResult.evaluated_at))
    if policy_ids:
        q = q.where(ConformityResult.policy_id.in_(list(policy_ids)))
    rows = (await db.execute(q)).scalars().all()
    seen: set[tuple[str, str, str]] = set()
    grouped: dict[str, list[ConformityResult]] = {}
    for r in rows:
        key = (str(r.policy_id), r.resource_kind, r.resource_id)
        if key in seen:
            continue
        seen.add(key)
        grouped.setdefault(str(r.policy_id), []).append(r)
    return grouped


def _esc(value: object) -> str:
    """Escape DB- or request-sourced text for reportlab's ``Paragraph``.

    ``Paragraph`` parses a mini-XML dialect, so an unescaped ``<?`` in the
    framework filter (or a stored policy name) raises ``paraparser: syntax
    error`` and 500s the export; the quieter case, ``<legacy>``, silently
    vanishes from the document. Every value interpolated into a Paragraph
    goes through here; the literal ``<b>`` / ``<font>`` markup around it
    stays ours.
    """
    return escape("" if value is None else str(value))


def _result_hash(rows: Iterable[ConformityResult]) -> str:
    """Stable hash over (id, status) tuples — auditor's tamper check."""
    digest = hashlib.sha256()
    items = sorted(
        ((str(r.id), r.status) for r in rows),
        key=lambda p: p[0],
    )
    for rid, status in items:
        digest.update(rid.encode())
        digest.update(b":")
        digest.update(status.encode())
        digest.update(b"\n")
    return digest.hexdigest()


# ── PDF rendering ───────────────────────────────────────────────────


_STATUS_COLORS = {
    "pass": colors.HexColor("#15803d"),
    "fail": colors.HexColor("#b91c1c"),
    "warn": colors.HexColor("#b45309"),
    "not_applicable": colors.HexColor("#525252"),
}


async def generate_conformity_pdf(
    db: AsyncSession,
    *,
    framework: str | None = None,
    title: str | None = None,
) -> bytes:
    """Render the latest conformity results as a PDF and return bytes.

    ``framework`` filters to a single framework (e.g.
    ``"PCI-DSS 4.0"``) — useful when an auditor only needs PCI
    evidence. ``None`` includes every framework grouped in
    alphabetical order.

    The render pass is synchronous reportlab, and THIS FUNCTION already
    runs it in ``asyncio.to_thread`` — a caller must simply await it.
    Do not wrap the call in ``asyncio.to_thread`` as well: handing a
    worker thread an async function returns an un-awaited coroutine
    instead of PDF bytes, and fails silently apart from a
    ``coroutine was never awaited`` warning.
    """
    pol_q = select(ConformityPolicy)
    if framework:
        pol_q = pol_q.where(ConformityPolicy.framework == framework)
    policies = sorted(
        (await db.execute(pol_q)).scalars().all(),
        key=lambda p: (p.framework, p.reference or "", p.name),
    )

    by_policy = await _latest_results_per_policy(
        db, policy_ids=[str(p.id) for p in policies] or None
    )
    all_rows: list[ConformityResult] = [r for rows in by_policy.values() for r in rows]
    integrity = _result_hash(all_rows)

    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=LETTER,
        leftMargin=0.75 * inch,
        rightMargin=0.75 * inch,
        topMargin=0.75 * inch,
        bottomMargin=0.75 * inch,
        title=title or "SpatiumDDI conformity report",
    )
    styles = getSampleStyleSheet()
    h1 = styles["Heading1"]
    h2 = styles["Heading2"]
    body = styles["BodyText"]
    small = ParagraphStyle("small", parent=body, fontSize=8, leading=10)
    mono = ParagraphStyle("mono", parent=body, fontName="Courier", fontSize=8, leading=10)

    story: list = []
    now = datetime.now(UTC)

    story.append(Paragraph(_esc(title or "SpatiumDDI conformity report"), h1))
    story.append(
        Paragraph(
            f"Generated {now.isoformat()} UTC · "
            f"{len(policies)} policies · {len(all_rows)} latest results",
            small,
        )
    )
    if framework:
        story.append(Paragraph(f"Framework filter: {_esc(framework)}", small))
    story.append(Spacer(1, 0.2 * inch))

    if not policies:
        story.append(
            Paragraph(
                "No conformity policies are configured. Enable a "
                "built-in policy under Administration → Conformity "
                "to populate this report.",
                body,
            )
        )
        # reportlab's render pass is synchronous CPU work; on the single-
        # worker uvicorn loop it stalls every request AND the kubelet's
        # 1s-budget probes, so it runs on a worker thread.
        await asyncio.to_thread(doc.build, story)
        return buf.getvalue()

    # Per-framework summary table.
    summary_rows: list[list[str]] = [["Framework", "Policies", "Pass", "Warn", "Fail", "N/A"]]
    counts: dict[str, dict[str, int]] = {}
    for p in policies:
        bucket = counts.setdefault(
            p.framework,
            {"policies": 0, "pass": 0, "warn": 0, "fail": 0, "not_applicable": 0},
        )
        bucket["policies"] += 1
        for r in by_policy.get(str(p.id), []):
            bucket[r.status] = bucket.get(r.status, 0) + 1
    for fw in sorted(counts.keys()):
        b = counts[fw]
        summary_rows.append(
            [
                fw,
                str(b["policies"]),
                str(b.get("pass", 0)),
                str(b.get("warn", 0)),
                str(b.get("fail", 0)),
                str(b.get("not_applicable", 0)),
            ]
        )
    summary_table = Table(summary_rows, hAlign="LEFT")
    summary_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("LINEBELOW", (0, 0), (-1, 0), 0.5, colors.grey),
                ("ALIGN", (1, 1), (-1, -1), "RIGHT"),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
            ]
        )
    )
    story.append(summary_table)
    story.append(Spacer(1, 0.25 * inch))

    # Per-policy section.
    by_framework: dict[str, list[ConformityPolicy]] = {}
    for p in policies:
        by_framework.setdefault(p.framework, []).append(p)
    for fw in sorted(by_framework.keys()):
        story.append(PageBreak())
        story.append(Paragraph(_esc(fw), h1))
        story.append(Spacer(1, 0.1 * inch))
        for policy in by_framework[fw]:
            ref = f" ({policy.reference})" if policy.reference else ""
            story.append(Paragraph(f"{_esc(policy.name)}{_esc(ref)}", h2))
            story.append(
                Paragraph(
                    f"Severity: {_esc(policy.severity)} · check: {_esc(policy.check_kind)}"
                    f" · target: {_esc(policy.target_kind)}",
                    small,
                )
            )
            if policy.description:
                story.append(Paragraph(_esc(policy.description), body))
            story.append(Spacer(1, 0.05 * inch))

            results = by_policy.get(str(policy.id), [])
            tally = {"pass": 0, "fail": 0, "warn": 0, "not_applicable": 0}
            failing: list[ConformityResult] = []
            for r in results:
                tally[r.status] = tally.get(r.status, 0) + 1
                if r.status in ("fail", "warn"):
                    failing.append(r)
            story.append(
                Paragraph(
                    f"<font color='{_STATUS_COLORS['pass'].hexval()}'>"
                    f"<b>{tally['pass']}</b> pass</font> · "
                    f"<font color='{_STATUS_COLORS['warn'].hexval()}'>"
                    f"<b>{tally['warn']}</b> warn</font> · "
                    f"<font color='{_STATUS_COLORS['fail'].hexval()}'>"
                    f"<b>{tally['fail']}</b> fail</font> · "
                    f"<font color='{_STATUS_COLORS['not_applicable'].hexval()}'>"
                    f"<b>{tally['not_applicable']}</b> n/a</font>",
                    body,
                )
            )

            if not failing:
                story.append(Paragraph("No failing rows.", small))
            else:
                for r in failing:
                    story.append(
                        Paragraph(
                            f"<b>[{_esc(r.status.upper())}] {_esc(r.resource_display)}</b>"
                            f" · {_esc(r.detail or '(no detail)')}",
                            small,
                        )
                    )
                    if r.diagnostic:
                        try:
                            blob = json.dumps(r.diagnostic, indent=2, default=str)
                        except (TypeError, ValueError):
                            blob = repr(r.diagnostic)
                        story.append(Paragraph(_esc(blob).replace("\n", "<br/>"), mono))
            story.append(Spacer(1, 0.15 * inch))

    # Trailer.
    story.append(PageBreak())
    story.append(Paragraph("Integrity", h2))
    story.append(
        Paragraph(
            "The hash below covers every result row included in this "
            "report. An auditor can re-run the export and compare the "
            "hash to verify the underlying rows haven't been altered.",
            body,
        )
    )
    story.append(Spacer(1, 0.05 * inch))
    story.append(Paragraph(f"SHA-256: <font face='Courier'>{integrity}</font>", small))
    story.append(
        Paragraph(
            f"Result rows: {len(all_rows)} · " f"Generated: {now.isoformat()} UTC",
            small,
        )
    )
    story.append(Spacer(1, 0.5 * inch))
    story.append(
        Paragraph(
            "______________________________________ " "    Signature / date",
            small,
        )
    )

    # reportlab's render pass is synchronous CPU work; on the single-
    # worker uvicorn loop it stalls every request AND the kubelet's
    # 1s-budget probes, so it runs on a worker thread.
    await asyncio.to_thread(doc.build, story)
    return buf.getvalue()


__all__ = ["generate_conformity_pdf"]
