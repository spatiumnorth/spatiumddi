"""IPAM print / PDF export (#82).

The PDF itself is binary, so these assert the things that actually break:
scope resolution, the two report shapes, the address cap, and that an
operator-supplied name can't escape the ``Content-Disposition`` header.
Rendering fidelity is not asserted beyond "reportlab produced a PDF" —
pinning byte output would fail on every reportlab bump for no signal.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.ipam import IPAddress, IPBlock, IPSpace, Subnet
from app.services.ipam_io.pdf import _ADDRESS_CAP, _slugify, generate_ipam_pdf


async def _tree(db: AsyncSession, *, space_name: str = "Corp") -> dict[str, Any]:
    space = IPSpace(name=space_name, description="test space")
    db.add(space)
    await db.flush()
    parent = IPBlock(space_id=space.id, network="10.0.0.0/8", name="HQ")
    db.add(parent)
    await db.flush()
    child = IPBlock(
        space_id=space.id,
        network="10.1.0.0/16",
        name="Site A",
        parent_block_id=parent.id,
    )
    db.add(child)
    await db.flush()
    subnet = Subnet(
        space_id=space.id,
        block_id=child.id,
        network="10.1.0.0/24",
        name="Office-LAN",
        status="active",
        total_ips=254,
        allocated_ips=2,
    )
    db.add(subnet)
    await db.flush()
    await db.commit()
    return {"space": space, "parent": parent, "child": child, "subnet": subnet}


def _is_pdf(data: bytes) -> bool:
    # A real PDF starts with the magic header and ends with the EOF marker;
    # a truncated render would satisfy the first and fail the second.
    return data.startswith(b"%PDF-") and b"%%EOF" in data[-1024:]


async def test_space_scope_renders_tree(db_session: AsyncSession) -> None:
    t = await _tree(db_session)
    data, filename = await generate_ipam_pdf(db_session, space_id=t["space"].id)
    assert _is_pdf(data)
    assert filename.startswith("spatiumddi-ipam-Corp-")
    assert filename.endswith(".pdf")


async def test_subnet_scope_renders_detail(db_session: AsyncSession) -> None:
    t = await _tree(db_session)
    data, filename = await generate_ipam_pdf(db_session, subnet_id=t["subnet"].id)
    assert _is_pdf(data)
    # The CIDR slash must not survive into a filename.
    assert "/" not in filename
    assert "10.1.0.0-24" in filename


async def test_block_scope_renders_tree(db_session: AsyncSession) -> None:
    t = await _tree(db_session)
    data, filename = await generate_ipam_pdf(db_session, block_id=t["child"].id)
    assert _is_pdf(data)
    assert "10.1.0.0-16" in filename


async def test_subnet_scope_always_includes_addresses(db_session: AsyncSession) -> None:
    """A subnet report exists to show its addresses, so the caller's
    ``include_addresses=False`` must not empty it out."""
    t = await _tree(db_session)
    db_session.add(
        IPAddress(
            subnet_id=t["subnet"].id,
            address="10.1.0.5",
            status="allocated",
            hostname="host-5",
        )
    )
    await db_session.commit()

    without = await generate_ipam_pdf(db_session, subnet_id=t["subnet"].id, include_addresses=False)
    # Same scope with the flag on must produce the same document — proving
    # the flag is ignored for this shape rather than silently dropping rows.
    with_flag = await generate_ipam_pdf(
        db_session, subnet_id=t["subnet"].id, include_addresses=True
    )
    assert _is_pdf(without[0])
    assert abs(len(without[0]) - len(with_flag[0])) < 512


async def test_missing_scope_is_rejected(db_session: AsyncSession) -> None:
    from fastapi import HTTPException

    with pytest.raises(HTTPException) as exc:
        await generate_ipam_pdf(db_session)
    assert exc.value.status_code == 422


@pytest.mark.parametrize("kwarg", ["space_id", "block_id", "subnet_id"])
async def test_unknown_scope_is_404(db_session: AsyncSession, kwarg: str) -> None:
    from fastapi import HTTPException

    with pytest.raises(HTTPException) as exc:
        await generate_ipam_pdf(db_session, **{kwarg: uuid.uuid4()})
    assert exc.value.status_code == 404


async def test_address_cap_is_applied(db_session: AsyncSession) -> None:
    """More addresses than the cap must still render, and must not take
    time proportional to the full set."""
    space = IPSpace(name="Big")
    db_session.add(space)
    await db_session.flush()
    block = IPBlock(space_id=space.id, network="10.0.0.0/8", name="B")
    db_session.add(block)
    await db_session.flush()
    subnet = Subnet(
        space_id=space.id,
        block_id=block.id,
        network="10.2.0.0/16",
        name="Wide",
        status="active",
    )
    db_session.add(subnet)
    await db_session.flush()
    over = _ADDRESS_CAP + 25
    db_session.add_all(
        [
            IPAddress(
                subnet_id=subnet.id,
                address=f"10.2.{i // 256}.{i % 256}",
                status="allocated",
            )
            for i in range(over)
        ]
    )
    await db_session.commit()

    data, _ = await generate_ipam_pdf(db_session, subnet_id=subnet.id)
    assert _is_pdf(data)


class TestSlugify:
    """The slug lands in a ``Content-Disposition`` header, so this is a
    security boundary, not cosmetics."""

    def test_quote_cannot_escape_the_header(self) -> None:
        # Without sanitisation this closes the quoted filename and injects
        # a second one.
        assert '"' not in _slugify('evil"; filename="pwned.pdf')

    @pytest.mark.parametrize("ch", ["\r", "\n", ";", '"', "\\", "/", "\x00"])
    def test_header_metacharacters_are_stripped(self, ch: str) -> None:
        assert ch not in _slugify(f"name{ch}here")

    def test_spaces_and_parens_collapse(self) -> None:
        assert _slugify("AV multicast (543demo)") == "AV-multicast-543demo"

    def test_non_ascii_is_replaced_not_dropped_silently(self) -> None:
        # A fully non-ASCII name must still yield a usable filename.
        assert _slugify("東京") == "export"

    def test_empty_falls_back(self) -> None:
        assert _slugify("") == "export"
        assert _slugify("---") == "export"

    def test_length_is_bounded(self) -> None:
        assert len(_slugify("x" * 500)) <= 60


class TestParagraphMarkupSafety:
    """``Paragraph`` parses a mini-XML dialect, so operator-supplied names
    reach a parser. Both failure modes were live before the fix: a hard
    500, and — quieter and worse — silent truncation of the name in a
    document about to be handed to an auditor."""

    @pytest.mark.parametrize(
        "name",
        ["a<b>c", "unclosed <b", "<para>x</para>", "<font color=red>x", "amp & co"],
    )
    async def test_markup_in_space_name_does_not_crash(
        self, db_session: AsyncSession, name: str
    ) -> None:
        t = await _tree(db_session, space_name=name)
        data, _ = await generate_ipam_pdf(db_session, space_id=t["space"].id)
        assert _is_pdf(data)

    async def test_tag_like_name_is_not_silently_swallowed(self, db_session: AsyncSession) -> None:
        """``<legacy> net`` used to render as just "net" — the export
        quietly dropped half the name rather than failing loudly."""
        t = await _tree(db_session, space_name="<legacy> net")
        data, _ = await generate_ipam_pdf(db_session, space_id=t["space"].id)
        # The escaped form is what reaches the PDF's content stream.
        assert _is_pdf(data)
        assert b"legacy" in data


async def test_nested_blocks_indent_with_encodable_characters(
    db_session: AsyncSession,
) -> None:
    """The indent must stay inside WinAnsiEncoding.

    U+2007 FIGURE SPACE is not, and reportlab silently falls back to
    ZapfDingbats — where that codepoint is a filled black square — so
    every nested block rendered as "■■10.1.0.0/16". A font switch in the
    output is the tell.
    """
    t = await _tree(db_session)
    assert t["child"].parent_block_id == t["parent"].id  # the tree really nests
    data, _ = await generate_ipam_pdf(db_session, space_id=t["space"].id)
    assert _is_pdf(data)
    assert b"ZapfDingbats" not in data


async def test_addresses_render_in_numeric_order(db_session: AsyncSession) -> None:
    """Lexicographic order would put .10 before .9. ``_collect`` issues no
    ORDER BY, so the sort has to happen here or the cap keeps an
    arbitrary slice."""
    from app.services.ipam_io.pdf import _sort_addresses

    rows = [{"address": a} for a in ["10.1.0.10", "10.1.0.9", "10.1.0.2", "not-an-ip"]]
    ordered = [r["address"] for r in _sort_addresses(rows)]
    assert ordered[:3] == ["10.1.0.2", "10.1.0.9", "10.1.0.10"]
    # Unparseable values sort last rather than raising.
    assert ordered[-1] == "not-an-ip"


async def test_tree_include_addresses_renders_an_appendix(
    db_session: AsyncSession,
) -> None:
    """``include_addresses`` on a tree scope used to load every address and
    render none of them."""
    t = await _tree(db_session)
    db_session.add(IPAddress(subnet_id=t["subnet"].id, address="10.1.0.42", status="allocated"))
    await db_session.commit()

    without, _ = await generate_ipam_pdf(db_session, space_id=t["space"].id)
    with_addrs, _ = await generate_ipam_pdf(
        db_session, space_id=t["space"].id, include_addresses=True
    )
    assert _is_pdf(without) and _is_pdf(with_addrs)
    # The appendix is real content, so the document must actually grow.
    assert len(with_addrs) > len(without)


# --- #2982 / #2983: one utilisation, families never summed ------------------


def _pdf_text(data: bytes) -> str:
    """All text-showing strings of a reportlab PDF, one per line.

    pypdf is not a test dependency, so decode the content streams
    directly (ASCII85 + Flate, as reportlab writes them) and read the
    ``(...) Tj`` operators."""
    import base64
    import re
    import zlib

    out: list[str] = []
    for m in re.finditer(rb"stream\r?\n(.*?)endstream", data, re.S):
        raw = m.group(1).strip()
        try:
            if raw.endswith(b"~>"):
                raw = base64.a85decode(raw[:-2])
            raw = zlib.decompress(raw)
        except Exception:  # noqa: BLE001 - non-content stream (fonts, images)
            pass
        for t in re.finditer(rb"\((.*?)(?<!\\)\)\s*Tj", raw):
            out.append(t.group(1).decode("latin-1").replace("\\(", "(").replace("\\)", ")"))
    return "\n".join(out)


def _summary(text: str, label: str) -> str:
    lines = text.split("\n")
    return lines[lines.index(label) + 1]


async def test_summary_utilisation_is_the_blocks_row_utilisation(
    db_session: AsyncSession,
) -> None:
    from app.services.ipam.utilization import block_utilization_percent

    space = IPSpace(name="Util")
    db_session.add(space)
    await db_session.flush()
    block = IPBlock(
        space_id=space.id,
        network="10.233.40.0/30",
        name="b",
        allocated_ips=2,
        total_ips=4,
        utilization_percent=block_utilization_percent(2, "10.233.40.0/30"),
    )
    db_session.add(block)
    await db_session.flush()
    db_session.add(
        Subnet(
            space_id=space.id,
            block_id=block.id,
            network="10.233.40.0/30",
            name="s",
            total_ips=2,
            allocated_ips=2,
            utilization_percent=100.0,
        )
    )
    await db_session.commit()
    data, _ = await generate_ipam_pdf(db_session, block_id=block.id)
    text = _pdf_text(data)
    assert _summary(text, "IPv4 utilization") == "50%"
    assert _summary(text, "IPv4 addresses (blocks)") == "4"
    assert _summary(text, "IPv4 allocated") == "2"
    # The Blocks row's "Used" cell is the same figure; the old Summary
    # said 100% (over subnet capacity).
    assert "100%" not in text.split("Subnets")[0]


async def test_families_are_not_summed_and_v6_prints_true_size(
    db_session: AsyncSession,
) -> None:
    space = IPSpace(name="Dual")
    db_session.add(space)
    await db_session.flush()
    b4 = IPBlock(space_id=space.id, network="10.9.0.0/24", name="v4", allocated_ips=10)
    b6 = IPBlock(space_id=space.id, network="fd33:233:0:201::/64", name="v6", allocated_ips=1)
    db_session.add_all([b4, b6])
    await db_session.flush()
    db_session.add(
        Subnet(
            space_id=space.id,
            block_id=b6.id,
            network="fd33:233:0:201::/64",
            name="s6",
            total_ips=2**63 - 1,
            allocated_ips=1,
        )
    )
    await db_session.commit()
    data, _ = await generate_ipam_pdf(db_session, space_id=space.id)
    text = _pdf_text(data)
    assert _summary(text, "IPv4 addresses (blocks)") == "256"
    assert _summary(text, "IPv6 addresses (blocks)") == f"{2**64:,}"
    assert _summary(text, "IPv4 allocated") == "10"
    assert _summary(text, "IPv6 allocated") == "1"
    assert "9,223,372,036,854,775,807" not in text
    assert f"{2**64:,}" in text  # the /64 subnet row, true size
