"""A custom field value the API stored as a list or object reads as JSON text
in the PDF export and the search hit label, never as Python's repr (#4421)."""

from __future__ import annotations

from app.services.custom_field_text import custom_field_text
from app.services.ipam_io.pdf import _custom_field_rows
from app.services.search.providers import _custom_field_hit


def test_text_form() -> None:
    assert custom_field_text("plain") == "plain"
    assert custom_field_text(7) == "7"
    assert custom_field_text({"k": "v"}) == '{"k":"v"}'
    assert custom_field_text(["a", "b"]) == '["a","b"]'


def test_pdf_rows_print_json_not_repr() -> None:
    rows = dict(
        _custom_field_rows(
            {"xp_plain": "plain-1", "xp_obj": {"k": "obj-1"}, "xp_list": ["list-a", "list-b"]}
        )
    )
    assert rows["xp_plain"] == "plain-1"
    assert rows["xp_obj"] == '{"k":"obj-1"}'
    assert rows["xp_list"] == '["list-a","list-b"]'


def test_search_label_prints_json_not_repr() -> None:
    _, obj = _custom_field_hit("objfind-7", {"xp_find": {"k": "objfind-7"}}, ["xp_find"])
    assert obj == 'custom_field:xp_find={"k":"objfind-7"}'
    _, lst = _custom_field_hit("listfind-7a", {"xp_find": ["listfind-7a", "b"]}, ["xp_find"])
    assert lst == 'custom_field:xp_find=["listfind-7a","b"]'
    _, plain = _custom_field_hit("plainfind-7", {"xp_find": "plainfind-7"}, ["xp_find"])
    assert plain == "custom_field:xp_find=plainfind-7"
