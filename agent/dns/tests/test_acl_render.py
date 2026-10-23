"""Named ACLs render into named.conf (issue #899).

Before this the agent never emitted an ``acl {}`` stanza at all — the
bundle carried ``{id, name}`` with no entries, so an ACL an operator
created was stored, listed, editable, and applied to nothing. Referencing
one from a view or from ``options`` therefore left an undefined symbol:
``named-checkconf`` fails and the agent declines the *whole* bundle, so
the group stops converging rather than just that statement.

The load-bearing assertion here is **placement**. An ``acl`` in BIND is
resolved where it is written, so a definition below its first use is an
error, not a forward declaration.
"""

from __future__ import annotations

from pathlib import Path

from spatium_dns_agent.drivers.bind9 import Bind9Driver, _render_acl_statements


def _bundle(acls: list[dict], views: list[dict] | None = None) -> dict:
    return {
        "server": {"name": "s1", "driver": "bind9"},
        "options": {},
        "acls": acls,
        "views": views or [],
        "zones": [],
        "blocklists": [],
        "tsig_keys": [],
        "pending_ops": [],
    }


def _acl(name: str, *values: str) -> dict:
    return {
        "id": name,
        "name": name,
        "entries": [
            {"value": v.lstrip("!"), "negate": v.startswith("!")} for v in values
        ],
    }


# ── the helper ────────────────────────────────────────────────────────────


def test_renders_entries_with_negation() -> None:
    out = _render_acl_statements([_acl("office", "10.0.0.0/8", "!192.168.0.0/16")])
    assert out == 'acl "office" { 10.0.0.0/8; !192.168.0.0/16; };\n'


def test_an_empty_acl_renders_as_none_not_skipped() -> None:
    """BIND rejects ``acl "x" { };`` — but omitting the definition is worse.

    The name may already be cited by a view or another ACL, and dropping it
    re-creates the undefined-symbol outage this whole change removes.
    ``none`` is also the honest meaning of an empty address-match list.
    """
    assert (
        _render_acl_statements([{"name": "empty", "entries": []}])
        == 'acl "empty" { none; };\n'
    )
    assert (
        _render_acl_statements([{"name": "blank", "entries": [{"value": "  "}]}])
        == 'acl "blank" { none; };\n'
    )
    # A nameless ACL has nothing to render or cite.
    assert _render_acl_statements([{"name": "", "entries": [{"value": "any"}]}]) == ""
    assert _render_acl_statements([]) == ""
    assert _render_acl_statements(None) == ""


def test_negation_is_not_doubled() -> None:
    """Negation is a flag on the row, but an operator can equally paste
    ``!10.0.0.0/8`` into the value. Rendering both gives ``!!…``, which
    BIND rejects."""
    assert _render_acl_statements(
        [{"name": "a", "entries": [{"value": "!10.0.0.0/8", "negate": True}]}]
    ) == 'acl "a" { !10.0.0.0/8; };\n'
    assert _render_acl_statements(
        [{"name": "a", "entries": [{"value": "!10.0.0.0/8", "negate": False}]}]
    ) == 'acl "a" { !10.0.0.0/8; };\n'



# ── through the real renderer ─────────────────────────────────────────────


def test_acls_are_written_above_options(tmp_path: Path) -> None:
    """``options`` cites ACLs in allow-query / allow-transfer, so the
    definitions have to precede it — this is the whole correctness
    property, and it is invisible in a diff of the helper alone."""
    drv = Bind9Driver(state_dir=tmp_path)
    drv.render(_bundle([_acl("office", "10.0.0.0/8")]))
    conf = (tmp_path / "rendered.new" / "named.conf").read_text()

    assert 'acl "office" { 10.0.0.0/8; };' in conf
    assert conf.index('acl "office"') < conf.index("options {")


def test_acls_precede_the_views_that_reference_them(tmp_path: Path) -> None:
    drv = Bind9Driver(state_dir=tmp_path)
    drv.render(
        _bundle(
            [_acl("office", "10.0.0.0/8")],
            views=[
                {
                    "name": "internal",
                    "match_clients": ["office"],
                    "match_destinations": [],
                    "recursion": True,
                    "order": 0,
                }
            ],
        )
    )
    conf = (tmp_path / "rendered.new" / "named.conf").read_text()
    assert "match-clients { office; };" in conf
    assert conf.index('acl "office"') < conf.index('view "internal"')


def test_a_bundle_with_no_acls_renders_unchanged(tmp_path: Path) -> None:
    """Every existing install has zero ACLs. Their named.conf must not
    move — a changed byte churns the config hash and reloads BIND for
    nothing."""
    drv = Bind9Driver(state_dir=tmp_path)
    drv.render(_bundle([]))
    conf = (tmp_path / "rendered.new" / "named.conf").read_text()
    assert "acl " not in conf
    assert conf.lstrip().startswith("options {")


# ── forward policy ────────────────────────────────────────────────────────
#
# Not an ACL, but the same class of bug and found by the #899 audit:
# ``DNSServerOptions.forward_policy`` was settable, persisted and shipped
# in the bundle, and no ``forward`` statement was ever rendered.


def _forwarder_bundle(policy: str) -> dict:
    b = _bundle([])
    # The agent reads forwarders from ``options``, not the bundle root.
    b["options"] = {"forwarders": ["9.9.9.9"], "forward_policy": policy}
    return b


def test_forward_only_is_rendered(tmp_path: Path) -> None:
    """``only`` means "never fall back to recursing yourself" — it is how an
    operator forces every query through a filtering upstream. Rendering
    nothing left BIND on its default (``first``), which lets queries leak
    straight past that filter."""
    drv = Bind9Driver(state_dir=tmp_path)
    drv.render(_forwarder_bundle("only"))
    conf = (tmp_path / "rendered.new" / "named.conf").read_text()
    assert "forwarders { 9.9.9.9; };" in conf
    assert "forward only;" in conf


def test_forward_first_renders_nothing_extra(tmp_path: Path) -> None:
    """``first`` IS BIND's default, so emitting it would change named.conf
    on every install that has forwarders and reload BIND for no behaviour
    change."""
    drv = Bind9Driver(state_dir=tmp_path)
    drv.render(_forwarder_bundle("first"))
    conf = (tmp_path / "rendered.new" / "named.conf").read_text()
    assert "forwarders { 9.9.9.9; };" in conf
    assert "forward " not in conf


def test_no_forward_statement_without_forwarders(tmp_path: Path) -> None:
    """``forward only;`` with no forwarders is a BIND config error."""
    drv = Bind9Driver(state_dir=tmp_path)
    b = _bundle([])
    b["options"] = {"forward_policy": "only"}
    drv.render(b)
    conf = (tmp_path / "rendered.new" / "named.conf").read_text()
    assert "forward only;" not in conf


# ── duplicate TSIG key names (#2295) ──────────────────────────────────────


def test_duplicate_tsig_key_names_render_one_key_statement(tmp_path: Path) -> None:
    """``foo`` / ``foo.`` / ``Foo`` are one key to BIND; two ``key`` statements
    make named-checkconf reject the file and the bundle be declined."""
    b = _bundle([])
    b["tsig_keys"] = [
        {"name": "spatium-g", "secret": "c2VjcmV0", "algorithm": "hmac-sha256"},
        {"name": "spatium-g", "secret": "ZGlmZg==", "algorithm": "hmac-sha256"},
        {"name": "foo", "secret": "c2VjcmV0", "algorithm": "hmac-sha256"},
        {"name": "foo.", "secret": "c2VjcmV0", "algorithm": "hmac-sha256"},
    ]
    drv = Bind9Driver(state_dir=tmp_path)
    drv.render(b)
    keyfile = (tmp_path / "rendered.new" / "tsig" / "ddns.key")
    if not keyfile.exists():
        keyfile = tmp_path / "tsig" / "ddns.key"
    text = keyfile.read_text()
    assert text.count('key "') == 2
    assert 'key "spatium-g"' in text and 'key "foo"' in text
