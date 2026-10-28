"""IPAM print / PDF export (#82).

A static, handover-shaped deliverable for an IPAM subtree: the address
plan as it stands, rendered server-side so what the operator hands an
auditor doesn't depend on their browser, zoom level, or which columns
they happened to have toggled on.

Two report shapes, chosen by scope — the same scope selector the
CSV / JSON / XLSX exporter already takes:

* **space or block** → *tree* report. Summary counters, the block
  hierarchy indented by nesting depth, then every subnet with its
  utilization.
* **subnet** → *detail* report. The subnet's own facts, its custom
  fields, and (opt-in) its address table.

Follows the reportlab pattern already shipped in
``services/conformity/pdf.py`` and ``services/audit_report.py`` — a
synchronous render after the async DB work, dispatched to a worker
thread so it cannot stall the event loop. The issue text proposed
weasyprint; adding a second PDF engine (plus its Cairo / Pango system
libraries) to render tables we already know how to render would be a
large dependency for no capability we don't have.

Unlike those two, this one paginates properly: repeating table headers
plus a numbered page footer, because a printed address plan is read as
paper and "page 3 of 11" is what makes it checkable.
"""

from __future__ import annotations

import asyncio
import io
import ipaddress
import uuid
from datetime import UTC, datetime
from typing import Any
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import LETTER, landscape
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.pdfgen import canvas as pdfcanvas
from reportlab.platypus import (
    KeepTogether,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.content_disposition import slugify_filename_part
from app.services.ipam.utilization import utilization_percent

# Same scope resolution + payload shaping the CSV/JSON/XLSX exporter uses,
# so a PDF and a spreadsheet of the same scope can't disagree about what
# the subtree contains. Intra-package use of the private helper is
# deliberate — promoting it to public API would imply a stability
# guarantee we don't need between two modules that ship together.
from app.services.ipam_io.export import ExportBundle, _collect

# Address rows are the only unbounded axis here — a /16 with every host
# enumerated is 65k rows, which is not a document anyone reads. Cap it and
# say so on the page, rather than emitting a 900-page PDF or silently
# truncating. Blocks and subnets are bounded by how many an operator has
# actually created, so they are not capped.
_ADDRESS_CAP = 2000

_HEADER_BG = colors.HexColor("#1f2937")
_ROW_ALT = colors.HexColor("#f3f4f6")
_GRIDLINE = colors.HexColor("#d1d5db")
_MUTED = colors.HexColor("#6b7280")


class _NumberedCanvas(pdfcanvas.Canvas):
    """Canvas that stamps "Page N of M" once the total is known.

    reportlab streams pages, so on the first pass the total page count
    doesn't exist yet. The standard fix, used here: buffer each page's
    state, then on ``save()`` replay them with the total in hand. Without
    it a footer can only say "Page 3", which tells a reader holding a
    printout nothing about whether they're missing page 4.
    """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        self._footer_left: str = kwargs.pop("footer_left", "")
        super().__init__(*args, **kwargs)
        self._saved: list[dict[str, Any]] = []

    def showPage(self) -> None:  # noqa: N802 — reportlab's API casing
        self._saved.append(dict(self.__dict__))
        self._startPage()

    def save(self) -> None:
        total = len(self._saved)
        for state in self._saved:
            self.__dict__.update(state)
            self._draw_footer(total)
            super().showPage()
        super().save()

    def _draw_footer(self, total: int) -> None:
        self.setFont("Helvetica", 7.5)
        self.setFillColor(_MUTED)
        width, _ = self._pagesize
        self.drawString(0.75 * inch, 0.5 * inch, self._footer_left)
        self.drawRightString(
            width - 0.75 * inch,
            0.5 * inch,
            f"Page {self._pageNumber} of {total}",
        )


def _grid(
    header: list[str],
    rows: list[list[str]],
    col_widths: list[float],
    *,
    align_right: tuple[int, ...] = (),
) -> Table:
    """Standard table. ``repeatRows=1`` is what keeps the column headers
    on every page — the other half of "stable headers" alongside the
    numbered footer."""
    style: list[Any] = [
        ("BACKGROUND", (0, 0), (-1, 0), _HEADER_BG),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, _ROW_ALT]),
        ("GRID", (0, 0), (-1, -1), 0.25, _GRIDLINE),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 2),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
    ]
    for col in align_right:
        style.append(("ALIGN", (col, 1), (col, -1), "RIGHT"))
    t = Table([header, *rows], colWidths=col_widths, repeatRows=1)
    t.setStyle(TableStyle(style))
    return t


def _pct(value: Any) -> str:
    """Utilization as a whole percent. ``None`` reads as an em dash rather
    than "0%" — an unknown figure and a genuinely empty subnet are not the
    same thing to whoever is reading the handover."""
    if value is None:
        return "—"
    try:
        return f"{float(value):.0f}%"
    except (TypeError, ValueError):
        return "—"


def _num(value: Any) -> str:
    if value is None:
        return "—"
    try:
        return f"{int(value):,}"
    except (TypeError, ValueError):
        return str(value)


def _cell(value: Any, limit: int = 40) -> str:
    """Truncate for a fixed-width column. Table cells are plain strings
    rather than Paragraphs so long values clip predictably instead of
    reflowing a row to three lines and pushing the grid off the page.

    Plain strings also mean no XML escaping is needed here — only
    ``Paragraph`` parses markup. See :func:`_para`.
    """
    if value is None or value == "":
        return "—"
    s = str(value)
    return s if len(s) <= limit else s[: limit - 1] + "…"


def _para(text: str, style: Any) -> Paragraph:
    """Build a Paragraph from untrusted text.

    ``Paragraph`` parses a mini-XML dialect, so operator-supplied names
    reach a parser. Unescaped, an IP space called ``a<b>c`` raises
    ``paraparser: syntax error`` and 500s the whole export — and the
    quieter case is worse: a space named ``<legacy> net`` renders as
    just "net", silently dropping part of the name from a document
    someone is about to hand an auditor. Escape at the boundary; every
    Paragraph built from DB content must go through here.
    """
    return Paragraph(escape(text), style)


def _block_depth_order(blocks: list[dict[str, Any]]) -> list[tuple[int, dict[str, Any]]]:
    """Order blocks parent-before-child, paired with their nesting depth.

    The bundle is a flat list with ``parent_block_id`` pointers, and the
    tree is the whole point of the report — a flat list of CIDRs doesn't
    show an auditor how the space is carved up. Blocks whose parent isn't
    in this bundle (a block-scoped export starts partway down) are roots
    for the purposes of this document.
    """
    by_id = {b["id"]: b for b in blocks}
    children: dict[str | None, list[dict[str, Any]]] = {}
    for b in blocks:
        parent = b.get("parent_block_id")
        # Treat an out-of-bundle parent as absent so the subtree still renders.
        key = parent if parent in by_id else None
        children.setdefault(key, []).append(b)

    def sort_key(b: dict[str, Any]) -> tuple[int, Any]:
        try:
            net = ipaddress.ip_network(str(b["network"]), strict=False)
            return (net.version, (int(net.network_address), net.prefixlen))
        except ValueError:
            return (99, str(b["network"]))

    out: list[tuple[int, dict[str, Any]]] = []

    def walk(parent: str | None, depth: int) -> None:
        for b in sorted(children.get(parent, []), key=sort_key):
            out.append((depth, b))
            walk(b["id"], depth + 1)

    walk(None, 0)
    # Defensive: a parent cycle would drop rows silently. Anything the walk
    # didn't reach gets appended flat so the document is never quietly
    # missing part of the estate.
    seen = {id(b) for _, b in out}
    out.extend((0, b) for b in blocks if id(b) not in seen)
    return out


def _sort_subnets(subnets: list[dict[str, Any]]) -> list[dict[str, Any]]:
    def key(s: dict[str, Any]) -> tuple[int, Any]:
        try:
            net = ipaddress.ip_network(str(s["network"]), strict=False)
            return (net.version, (int(net.network_address), net.prefixlen))
        except ValueError:
            return (99, str(s["network"]))

    return sorted(subnets, key=key)


def _slugify(value: str) -> str:
    """Reduce an operator-supplied name to a safe filename fragment.

    Thin alias for the shared implementation — this lands in a
    ``Content-Disposition`` header, and that rule now has one home
    (``app.core.content_disposition``) so the export routes, the PDF
    filenames and any future download agree about it.
    """
    return slugify_filename_part(value)


def _sort_addresses(addresses: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Numeric IP order. Lexicographic would put .10 before .9, and the
    address table is the part of the report an operator actually scans."""

    def key(a: dict[str, Any]) -> tuple[int, Any]:
        try:
            ip = ipaddress.ip_address(str(a.get("address")))
            return (ip.version, int(ip))
        except ValueError:
            return (99, str(a.get("address")))

    return sorted(addresses, key=key)


def _custom_field_rows(fields: dict[str, Any] | None) -> list[list[str]]:
    if not fields:
        return []
    return [[_cell(k, 30), _cell(v, 70)] for k, v in sorted(fields.items())]


def _family_summary_rows(blocks: list[dict[str, Any]]) -> list[list[str]]:
    """Summary rows per address family, from the scope's top-level blocks.

    Two rules (#2982, #2983). Families are never summed: an IPv4 address
    count and an IPv6 one are not the same unit, and adding them printed
    the IPv6 BIGINT clamp as a count. And the utilization is the
    *block's* — allocated over the block CIDR, the same helper the API
    uses — so the Summary and the Blocks table state one figure. Only
    top-level blocks (parent not in the bundle) are summed; their
    allocated count already rolls up every descendant.
    """
    ids = {b.get("id") for b in blocks}
    roots = [b for b in blocks if b.get("parent_block_id") not in ids]
    per_family: dict[int, list[int]] = {}
    for b in roots:
        try:
            net = ipaddress.ip_network(str(b["network"]), strict=False)
        except ValueError:
            continue
        acc = per_family.setdefault(net.version, [0, 0])
        acc[0] += net.num_addresses
        acc[1] += int(b.get("allocated_ips") or 0)
    rows: list[list[str]] = []
    for version in sorted(per_family):
        total, alloc = per_family[version]
        label = f"IPv{version}"
        rows += [
            [f"{label} addresses (blocks)", _num(total)],
            [f"{label} allocated", _num(alloc)],
            [f"{label} utilization", _pct(utilization_percent(alloc, total))],
        ]
    return rows


def _subnet_total(s: dict[str, Any]) -> str:
    """A subnet's size. The stored IPv6 total is clamped to BIGINT; print
    the real size instead, never the clamp as a count."""
    try:
        net = ipaddress.ip_network(str(s["network"]), strict=False)
    except (KeyError, ValueError):
        return _num(s.get("total_ips"))
    if net.version == 6:
        return _num(net.num_addresses)
    return _num(s.get("total_ips"))


def _build_tree_story(bundle: ExportBundle, styles: Any, scope_label: str) -> list[Any]:
    h2 = styles["Heading2"]
    small = styles["small"]
    story: list[Any] = []

    subnets = _sort_subnets(bundle.subnets)
    story.append(Paragraph("Summary", h2))
    story.append(
        _grid(
            ["Metric", "Value"],
            [
                ["Scope", _cell(scope_label, 60)],
                ["Blocks", _num(len(bundle.blocks))],
                ["Subnets", _num(len(subnets))],
                *_family_summary_rows(bundle.blocks),
            ],
            [2.2 * inch, 6.3 * inch],
        )
    )
    story.append(Spacer(1, 0.2 * inch))

    if bundle.blocks:
        rows = []
        for depth, b in _block_depth_order(bundle.blocks):
            # Plain ASCII spaces. U+2007 FIGURE SPACE looks like the
            # right character for aligned indentation, but it is not in
            # WinAnsiEncoding — reportlab silently substitutes
            # ZapfDingbats, where that codepoint is a filled black
            # square, so every nested block rendered as "■■10.5.0.0/16".
            # Verified against a real nested tree before and after.
            prefix = "    " * depth
            rows.append(
                [
                    f"{prefix}{_cell(b['network'], 44)}",
                    _cell(b.get("name"), 28),
                    _cell(b.get("description"), 44),
                    _pct(b.get("utilization_percent")),
                ]
            )
        story.append(KeepTogether([Paragraph("Blocks", h2), Spacer(1, 0.04 * inch)]))
        story.append(
            _grid(
                ["Network", "Name", "Description", "Used"],
                rows,
                [2.6 * inch, 1.9 * inch, 3.1 * inch, 0.9 * inch],
                align_right=(3,),
            )
        )
        story.append(Spacer(1, 0.2 * inch))

    story.append(Paragraph("Subnets", h2))
    if not subnets:
        story.append(Paragraph("No subnets in this scope.", small))
        return story + _tree_address_appendix(bundle, styles)
    story.append(
        _grid(
            ["Network", "Name", "Block", "VLAN", "Status", "Total", "Used", "%"],
            [
                [
                    _cell(s["network"], 44),
                    _cell(s.get("name"), 24),
                    _cell(s.get("block"), 22),
                    _cell(s.get("vlan_id"), 8),
                    _cell(s.get("status"), 12),
                    _subnet_total(s),
                    _num(s.get("allocated_ips")),
                    _pct(s.get("utilization_percent")),
                ]
                for s in subnets
            ],
            [
                1.75 * inch,
                1.5 * inch,
                1.4 * inch,
                0.55 * inch,
                0.85 * inch,
                0.7 * inch,
                0.65 * inch,
                0.6 * inch,
            ],
            align_right=(5, 6, 7),
        )
    )
    return story + _tree_address_appendix(bundle, styles)


def _tree_address_appendix(bundle: ExportBundle, styles: Any) -> list[Any]:
    """Allocated addresses across the whole scope, when asked for.

    ``include_addresses`` used to be accepted on the tree shape, load
    every address in the space, and then render none of them — a
    parameter that cost a full table scan and did nothing. Either it
    means something or it shouldn't be on the route; this is the former.
    Empty when the caller didn't ask, because ``_collect`` then never
    fetched any.
    """
    if not bundle.addresses:
        return []
    h2 = styles["Heading2"]
    small = styles["small"]
    addresses = _sort_addresses(bundle.addresses)
    shown = addresses[:_ADDRESS_CAP]

    out: list[Any] = [Spacer(1, 0.2 * inch), Paragraph("Addresses", h2)]
    if len(addresses) > len(shown):
        out.append(
            Paragraph(
                f"Showing the first {len(shown):,} of {len(addresses):,} addresses "
                f"(capped at {_ADDRESS_CAP:,} — use the CSV or XLSX export for the "
                f"full list).",
                small,
            )
        )
        out.append(Spacer(1, 0.06 * inch))
    out.append(
        _grid(
            ["Address", "Subnet", "Status", "Hostname", "MAC", "Description"],
            [
                [
                    _cell(a.get("address"), 40),
                    _cell(a.get("subnet"), 24),
                    _cell(a.get("status"), 12),
                    _cell(a.get("hostname"), 24),
                    _cell(a.get("mac_address"), 18),
                    _cell(a.get("description"), 26),
                ]
                for a in shown
            ],
            [
                1.7 * inch,
                1.4 * inch,
                0.8 * inch,
                1.5 * inch,
                1.2 * inch,
                1.4 * inch,
            ],
        )
    )
    return out


def _build_subnet_story(bundle: ExportBundle, styles: Any) -> list[Any]:
    h2 = styles["Heading2"]
    small = styles["small"]
    story: list[Any] = []
    subnet = bundle.subnets[0]

    story.append(Paragraph("Subnet", h2))
    story.append(
        _grid(
            ["Field", "Value"],
            [
                ["Network", _cell(subnet["network"], 60)],
                ["Name", _cell(subnet.get("name"), 60)],
                ["Description", _cell(subnet.get("description"), 90)],
                ["IP space", _cell(subnet.get("space"), 60)],
                ["Parent block", _cell(subnet.get("block"), 60)],
                ["Gateway", _cell(subnet.get("gateway"), 40)],
                ["VLAN", _cell(subnet.get("vlan_id"), 20)],
                ["VXLAN", _cell(subnet.get("vxlan_id"), 20)],
                ["Status", _cell(subnet.get("status"), 20)],
                ["Addressable IPs", _num(subnet.get("total_ips"))],
                ["Allocated", _num(subnet.get("allocated_ips"))],
                ["Utilization", _pct(subnet.get("utilization_percent"))],
            ],
            [2.2 * inch, 6.3 * inch],
        )
    )
    story.append(Spacer(1, 0.2 * inch))

    cf = _custom_field_rows(subnet.get("custom_fields"))
    if cf:
        story.append(Paragraph("Custom fields", h2))
        story.append(_grid(["Field", "Value"], cf, [2.2 * inch, 6.3 * inch]))
        story.append(Spacer(1, 0.2 * inch))

    story.append(Paragraph("Addresses", h2))
    addresses = bundle.addresses
    if not addresses:
        story.append(
            Paragraph(
                "No addresses recorded for this subnet, or addresses were "
                "not requested for this export.",
                small,
            )
        )
        return story

    # _collect issues no ORDER BY, so without this the cap would keep an
    # arbitrary 2000 rows that differ between runs — and even under the cap
    # the table would not be in address order, unlike blocks and subnets
    # which this module sorts explicitly.
    addresses = _sort_addresses(addresses)
    shown = addresses[:_ADDRESS_CAP]
    if len(addresses) > len(shown):
        story.append(
            Paragraph(
                f"Showing the first {len(shown):,} of {len(addresses):,} addresses "
                f"(capped at {_ADDRESS_CAP:,} — use the CSV or XLSX export for the "
                f"full list).",
                small,
            )
        )
        story.append(Spacer(1, 0.06 * inch))
    story.append(
        _grid(
            ["Address", "Status", "Hostname", "FQDN", "MAC", "Description"],
            [
                [
                    _cell(a.get("address"), 40),
                    _cell(a.get("status"), 12),
                    _cell(a.get("hostname"), 22),
                    _cell(a.get("fqdn"), 40),
                    _cell(a.get("mac_address"), 18),
                    _cell(a.get("description"), 28),
                ]
                for a in shown
            ],
            [
                1.4 * inch,
                0.8 * inch,
                1.5 * inch,
                2.0 * inch,
                1.3 * inch,
                1.5 * inch,
            ],
        )
    )
    return story


async def generate_ipam_pdf(
    db: AsyncSession,
    *,
    space_id: uuid.UUID | None = None,
    block_id: uuid.UUID | None = None,
    subnet_id: uuid.UUID | None = None,
    include_addresses: bool = False,
) -> tuple[bytes, str]:
    """Render an IPAM subtree as a PDF. Returns ``(pdf_bytes, filename)``.

    Exactly one of ``space_id`` / ``block_id`` / ``subnet_id`` selects the
    scope; ``_collect`` raises 404 / 422 for a bad one, matching the
    behaviour of the spreadsheet exporter.

    The render pass is synchronous reportlab, and THIS FUNCTION already
    runs it in ``asyncio.to_thread`` — a caller must simply await it.
    Do not wrap the call in ``asyncio.to_thread`` as well: handing a
    worker thread an async function returns an un-awaited coroutine
    instead of PDF bytes, and fails silently apart from a
    ``coroutine was never awaited`` warning.
    """
    # A subnet-detail report is worthless without its addresses, so the
    # flag is forced on for that scope; for a tree it stays opt-in because
    # the addresses aren't rendered there and fetching them would be pure
    # cost.
    want_addresses = include_addresses or subnet_id is not None
    bundle = await _collect(
        db,
        space_id=space_id,
        block_id=block_id,
        subnet_id=subnet_id,
        include_addresses=want_addresses,
    )

    is_detail = subnet_id is not None and bool(bundle.subnets)
    space_name = (bundle.space or {}).get("name") or "IPAM"
    if is_detail:
        scope_label = str(bundle.subnets[0]["network"])
        heading = f"Subnet {scope_label}"
        slug = _slugify(scope_label)
    elif block_id:
        blk = next((b for b in bundle.blocks if b["id"] == str(block_id)), None)
        scope_label = str(blk["network"]) if blk else space_name
        heading = f"IPAM tree — {scope_label}"
        slug = _slugify(scope_label)
    else:
        scope_label = space_name
        heading = f"IPAM tree — {space_name}"
        slug = _slugify(space_name)

    now = datetime.now(UTC)
    generated = now.strftime("%Y-%m-%d %H:%M:%S UTC")

    styles = getSampleStyleSheet()
    styles.add(
        ParagraphStyle("small", parent=styles["BodyText"], fontSize=8, leading=10, textColor=_MUTED)
    )

    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf,
        # Landscape: the subnet table is eight columns wide and portrait
        # forces every one of them to clip.
        pagesize=landscape(LETTER),
        leftMargin=0.75 * inch,
        rightMargin=0.75 * inch,
        topMargin=0.7 * inch,
        bottomMargin=0.75 * inch,
        title=heading,
        author="SpatiumDDI",
    )

    story: list[Any] = [
        _para(heading, styles["Heading1"]),
        _para(
            f"IP space {space_name} · generated {generated} · "
            f"point-in-time snapshot, not a live view",
            styles["small"],
        ),
        Spacer(1, 0.18 * inch),
    ]
    story += (
        _build_subnet_story(bundle, styles)
        if is_detail
        else _build_tree_story(bundle, styles, scope_label)
    )

    footer = f"SpatiumDDI · {heading} · generated {generated}"
    # reportlab's render pass is synchronous CPU work; on the single-worker
    # uvicorn loop it stalls every request AND the kubelet's probes, so it
    # runs on a worker thread. This is the largest of the three renderers —
    # a whole-space tree with the address appendix is a two-pass build over
    # every row in the subtree — so it is the one most able to blow the
    # probe budget, explicit ``timeoutSeconds`` included.
    await asyncio.to_thread(
        doc.build,
        story,
        canvasmaker=lambda *a, **kw: _NumberedCanvas(*a, footer_left=footer, **kw),
    )

    filename = f"spatiumddi-ipam-{slug}-{now.strftime('%Y%m%d-%H%M%S')}.pdf"
    return buf.getvalue(), filename
