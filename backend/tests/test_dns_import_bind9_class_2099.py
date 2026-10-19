"""#2099 — the BIND9 importer reads zones declared with a DNS class.

``zone "x" IN { … };`` is valid BIND (RHEL / Fedora's stock named.conf
writes every zone that way) and was silently skipped, as was every zone
inside ``view "v" IN { … };``. Non-IN zones are skipped with a stated
reason instead of being imported as IN.
"""

from __future__ import annotations

import io
import tarfile

import pytest

from app.services.dns_import import ImportSourceError, parse_bind9_archive

_ZONE = """\
$TTL 3600
@   IN  SOA ns1.{n}. admin.{n}. ( 1 3600 1800 1209600 3600 )
    IN  NS  ns1.{n}.
www IN  A   192.0.2.10
"""


def _archive(conf: str, names: list[str]) -> bytes:
    bio = io.BytesIO()
    with tarfile.open(fileobj=bio, mode="w:gz") as tf:
        members = [("etc/named.conf", conf)] + [(f"etc/{n}.db", _ZONE.format(n=n)) for n in names]
        for path, content in members:
            data = content.encode()
            info = tarfile.TarInfo(path)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return bio.getvalue()


def _names(conf: str, names: list[str]) -> list[str]:
    return sorted(z.name for z in parse_bind9_archive(_archive(conf, names)).zones)


def test_zone_with_class_is_imported() -> None:
    conf = 'zone "a.test" IN { type master; file "a.test.db"; };'
    assert _names(conf, ["a.test"]) == ["a.test."]


@pytest.mark.parametrize("cls", ["in", "In", "IN"])
def test_class_is_case_insensitive(cls: str) -> None:
    conf = f'zone "a.test" {cls} {{ type master; file "a.test.db"; }};'
    assert _names(conf, ["a.test"]) == ["a.test."]


def test_whitespace_newlines_and_comments_around_class() -> None:
    conf = (
        'zone "a.test"\n\t IN\n  /* the class */ { type master; file "a.test.db"; };\n'
        'zone "b.test" // trailing\n  IN // more\n{\n type master; file "b.test.db"; };\n'
        'zone "c.test"IN{ type master; file "c.test.db"; };\n'
    )
    assert _names(conf, ["a.test", "b.test", "c.test"]) == ["a.test.", "b.test.", "c.test."]


def test_view_with_class_keeps_its_zones() -> None:
    conf = """
view "internal" IN {
    match-clients { 10.0.0.0/8; };
    zone "a.test" IN { type master; file "a.test.db"; };
    zone "b.test" { type master; file "b.test.db"; };
};
"""
    preview = parse_bind9_archive(_archive(conf, ["a.test", "b.test"]))
    assert sorted(z.name for z in preview.zones) == ["a.test.", "b.test."]
    assert {z.view_name for z in preview.zones} == {"internal"}


def test_mixed_classes_import_only_in_and_unclassed() -> None:
    conf = """
zone "a.test" IN { type master; file "a.test.db"; };
zone "b.test" { type master; file "b.test.db"; };
zone "bind" CH { type master; file "bind.db"; };
zone "hs.test" hs { type master; file "hs.db"; };
"""
    preview = parse_bind9_archive(_archive(conf, ["a.test", "b.test"]))
    assert sorted(z.name for z in preview.zones) == ["a.test.", "b.test."]
    skipped = [w for w in preview.warnings if "skipped" in w]
    assert len(skipped) == 2
    assert any("'bind'" in w and "class CH" in w for w in skipped)
    assert any("'hs.test'" in w and "class HS" in w for w in skipped)


def test_chaos_view_zones_inherit_the_class() -> None:
    conf = """
view "chaos" CHAOS { zone "bind" { type master; file "bind.db"; }; };
zone "a.test" IN { type master; file "a.test.db"; };
"""
    preview = parse_bind9_archive(_archive(conf, ["a.test"]))
    assert [z.name for z in preview.zones] == ["a.test."]
    assert any("'bind'" in w and "class CH" in w for w in preview.warnings)


def test_only_non_in_zones_is_refused_with_the_reason() -> None:
    conf = 'zone "bind" CH { type master; file "bind.db"; };'
    with pytest.raises(ImportSourceError, match="none is class IN"):
        parse_bind9_archive(_archive(conf, []))


def test_no_class_form_still_works() -> None:
    conf = 'zone "a.test" { type master; file "a.test.db"; };'
    assert _names(conf, ["a.test"]) == ["a.test."]


def test_nested_braces_in_zone_body() -> None:
    conf = """
zone "a.test" IN {
    type master;
    file "a.test.db";
    allow-transfer { 10.0.0.1; { 10.0.0.2; }; };
    also-notify { 10.0.0.3; };
};
zone "b.test" IN { type master; file "b.test.db"; };
"""
    assert _names(conf, ["a.test", "b.test"]) == ["a.test.", "b.test."]


def test_identifier_ending_in_a_class_word_is_not_a_class() -> None:
    # ``INFO`` must not be read as ``IN`` + ``FO``.
    conf = 'zone "a.test" INFO { type master; };\nzone "b.test" { type master; file "b.test.db"; };'
    assert _names(conf, ["b.test"]) == ["b.test."]
