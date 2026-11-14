"""Delete dialogs name every table their delete cascades to (#4143-#4145).

``frontend/src/lib/delete-cascade.json`` is the registry the console's delete
confirm dialogs (Trash purge of a subnet / block / space, Multicast Delete
selected, IPAM Delete Permanently) read their "removed with it" lists from.
This test walks the SQLAlchemy foreign-key graph (``ondelete="CASCADE"``)
from each dialog's root table and fails when a table the database removes is
neither named by that dialog (or one it ``includes``) nor listed under
``exempt`` with a reason. So a new child table of an address, subnet, block,
space or multicast group cannot ship until its dialog says so.

Not covered: the other delete dialogs (zones, scopes, servers, ...) are not in
the registry yet; add one under ``dialogs`` and it is guarded the same way.

Skipped rather than failed when the frontend tree is absent: the api image
ships only ``backend/``. CI checks out the whole repo.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import app.models  # noqa: F401  (registers every table on Base.metadata)
from app.models.base import Base

_REGISTRY = Path(__file__).resolve().parents[2] / "frontend" / "src" / "lib" / "delete-cascade.json"

pytestmark = pytest.mark.skipif(not _REGISTRY.exists(), reason="frontend tree not present")


def _registry() -> dict:
    return json.loads(_REGISTRY.read_text())


def _cascade_children(table: str) -> set[str]:
    out: set[str] = set()
    for tb in Base.metadata.tables.values():
        for fk in tb.foreign_keys:
            if fk.column.table.name == table and (fk.ondelete or "").upper() == "CASCADE":
                out.add(tb.name)
    return out


def _closure(root: str) -> set[str]:
    seen: set[str] = set()
    todo = [root]
    while todo:
        for child in _cascade_children(todo.pop()):
            if child not in seen:
                seen.add(child)
                todo.append(child)
    return seen


def _scope(reg: dict, dialog: str) -> tuple[set[str], set[str]]:
    """(tables the dialog's delete removes, tables its copy names)."""
    d = reg["dialogs"][dialog]
    removed = _closure(d["root"])
    named = set(d["tables"])
    for inc in d["includes"]:
        r, n = _scope(reg, inc)
        removed |= r
        named |= n
    return removed, named


def test_every_cascaded_table_is_named_or_exempt() -> None:
    reg = _registry()
    for dialog in reg["dialogs"]:
        removed, named = _scope(reg, dialog)
        missing = sorted(removed - named - set(reg["exempt"]))
        assert not missing, (
            f"the {dialog} delete dialog does not name {missing}, which its delete "
            "removes through ondelete=CASCADE. Add each table to that dialog's "
            "'tables' in frontend/src/lib/delete-cascade.json (with a phrase under "
            "'tables'), or to 'exempt' with the reason it needs no word."
        )


def test_registry_only_names_real_tables() -> None:
    reg = _registry()
    known = set(Base.metadata.tables)
    names = set(reg["tables"]) | set(reg["exempt"])
    for d in reg["dialogs"].values():
        names |= set(d["tables"]) | {d["root"]}
    assert not sorted(names - known)
    for d in reg["dialogs"].values():
        assert set(d["tables"]) <= set(reg["tables"])
    assert not set(reg["tables"]) & set(reg["exempt"])


def test_the_reported_rows_are_named() -> None:
    reg = _registry()
    assert "av_flow_profile" in reg["dialogs"]["multicast_group"]["tables"]  # #4144
    assert {"ot_device", "bacnet_device"} <= set(reg["dialogs"]["ip_address"]["tables"])  # #4145
    _, named = _scope(reg, "ip_space")
    assert {"address_set", "ot_zone"} <= named  # #4143
