"""BIND9 agent query / response / RPZ logging block (issues #699, #914, #2249).

This renderer — not the control-plane Jinja template — is what every
agent-managed BIND9 server actually runs, and the two have drifted:
the template routed the ``rpz`` categories from #699 and this file never
did, so a policy rewrite was logged to a category pointing nowhere and
the whole per-client blocklist attribution reported nothing on the only
path that ships it. That is the "settable, stored, never rendered" class
of bug the ``allow_transfer`` (#734) and ``forward_policy`` (#899)
findings belong to, and the reason these assertions are on the RENDERED
config rather than on the stored options.
"""

from __future__ import annotations

from spatium_dns_agent.drivers.bind9 import (
    _render_logging_block,
    _render_query_log_option,
    _render_response_log_option,
)


def test_logging_off_renders_nothing() -> None:
    assert _render_logging_block({}) == ""
    assert _render_logging_block({"query_log_enabled": False}) == ""
    # An existing group must render a byte-identical named.conf.
    assert _render_response_log_option({"response_log_enabled": True}) == ""
    assert _render_query_log_option({}) == ""
    assert _render_query_log_option({"query_log_enabled": False}) == ""


def test_query_logging_renders_an_explicit_querylog() -> None:
    """The marker the runtime sync reads back (#2249), and what makes a
    fresh named start with query logging on without leaning on BIND's
    category-based defaulting."""
    assert _render_query_log_option({"query_log_enabled": True}) == "    querylog yes;\n"


def test_query_logging_routes_the_rpz_categories() -> None:
    """named logs a rewrite to ``rpz``, never to ``queries``.

    Without both lines the hit goes to a category with no channel and
    the attribution feature silently records nothing. PASSTHRU has its
    own category, so its absence would leave the exception half dark and
    the ``policy != PASSTHRU`` filters unreachable.
    """
    out = _render_logging_block({"query_log_enabled": True})
    assert "category queries { queries_channel; };" in out
    assert "category query-errors { queries_channel; };" in out
    assert "category rpz { queries_channel; };" in out
    assert "category rpz-passthru { queries_channel; };" in out
    assert out.rstrip().endswith("};")


def test_response_logging_needs_both_switches() -> None:
    """The category says WHERE the lines go; ``responselog`` says whether
    named emits them at all. Rendering one without the other gives the
    operator a toggle that changes named.conf and produces no data."""
    opts = {"query_log_enabled": True, "response_log_enabled": True}
    assert "category responses { queries_channel; };" in _render_logging_block(opts)
    assert _render_response_log_option(opts) == "    responselog yes;\n"


def test_response_logging_is_off_by_default() -> None:
    out = _render_logging_block({"query_log_enabled": True})
    assert "category responses" not in out
    assert _render_response_log_option({"query_log_enabled": True}) == ""


def test_response_logging_alone_renders_nothing() -> None:
    """The responses ride ``queries_channel``, which only exists inside
    the query-log block — so this combination has nowhere to write. The
    control plane 422s it; the renderer is the second line of defence."""
    opts = {"query_log_enabled": False, "response_log_enabled": True}
    assert _render_logging_block(opts) == ""
    assert _render_response_log_option(opts) == ""


# ── Runtime state, not just the file (issue #914) ─────────────────────


def _driver(tmp_path, conf_text: str):
    from spatium_dns_agent.drivers.bind9 import Bind9Driver

    driver = Bind9Driver(state_dir=tmp_path)
    rendered = tmp_path / driver.rendered_dir_name
    rendered.mkdir(parents=True, exist_ok=True)
    (rendered / "named.conf").write_text(conf_text)
    return driver


def _fake_rndc(monkeypatch, rc: int = 0, stderr: str = "") -> list[list[str]]:
    import subprocess

    calls: list[list[str]] = []

    def fake_run(cmd, **kwargs):  # type: ignore[no-untyped-def]
        calls.append(list(cmd))
        return subprocess.CompletedProcess(cmd, rc, "", stderr)

    monkeypatch.setattr(subprocess, "run", fake_run)
    return calls


def test_reconfig_asserts_query_logging_on(tmp_path, monkeypatch) -> None:
    """``rndc reconfig`` does not apply query logging either (#2249).

    Verified against BIND 9.20.29: a named started with query logging off
    stays off after a reconfig that adds the ``queries`` category, with or
    without ``querylog yes;``. #914 believed query logging followed its
    category on reload; it only does at startup. Without this call the
    DNS Queries tab stays empty until named restarts, and with response
    logging on every response line is dropped as an orphan.
    """
    calls = _fake_rndc(monkeypatch)
    driver = _driver(tmp_path, "options {\n    querylog yes;\n};\n")
    driver._sync_logging_runtime(["rndc"])
    assert calls == [["rndc", "querylog", "on"], ["rndc", "responselog", "off"]]


def test_reconfig_asserts_query_logging_off(tmp_path, monkeypatch) -> None:
    """And the other direction: a named started with query logging on keeps
    logging after a reconfig that removes it, until told otherwise."""
    calls = _fake_rndc(monkeypatch)
    driver = _driver(tmp_path, "options {\n    recursion yes;\n};\n")
    driver._sync_logging_runtime(["rndc"])
    assert calls == [["rndc", "querylog", "off"], ["rndc", "responselog", "off"]]


def test_responselog_is_not_mistaken_for_querylog(tmp_path, monkeypatch) -> None:
    """The two markers are read independently and anchored to a statement,
    so neither one's presence turns the other on."""
    calls = _fake_rndc(monkeypatch)
    driver = _driver(tmp_path, "options {\n    responselog yes;\n};\n")
    driver._sync_logging_runtime(["rndc"])
    assert ["rndc", "querylog", "off"] in calls
    assert ["rndc", "responselog", "on"] in calls


def test_markers_only_match_a_statement(tmp_path, monkeypatch) -> None:
    """A commented-out statement, or a zone whose name happens to be
    ``querylog``, is not the switch: only a real statement turns it on."""
    calls = _fake_rndc(monkeypatch)
    conf = (
        "options {\n"
        "    // querylog yes;\n"
        "    # responselog yes;\n"
        "};\n"
        'zone "querylog" { type primary; file "querylog yes;"; };\n'
        'zone "responselog.example" { type primary; file "x.db"; };\n'
    )
    driver = _driver(tmp_path, conf)
    driver._sync_logging_runtime(["rndc"])
    assert calls == [["rndc", "querylog", "off"], ["rndc", "responselog", "off"]]


def test_reconfig_asserts_response_logging_on(tmp_path, monkeypatch) -> None:
    """``rndc reconfig`` does not apply ``responselog``.

    Verified against BIND 9.20.26: the swapped-in config said
    ``responselog yes;``, the reconfig succeeded, and ``rndc status``
    still reported OFF. Without this call the operator gets a toggle
    that rewrites named.conf, validates, reloads — and logs nothing
    until the daemon next restarts.
    """
    calls = _fake_rndc(monkeypatch)
    driver = _driver(tmp_path, "options {\n    querylog yes;\n    responselog yes;\n};\n")
    driver._sync_logging_runtime(["rndc"])
    assert calls == [["rndc", "querylog", "on"], ["rndc", "responselog", "on"]]


def test_logging_sync_survives_an_old_named(tmp_path, monkeypatch) -> None:
    """A named with no ``responselog`` command is a legitimate reason to
    fail here, and the config-file value still applies at the next
    restart — so it warns rather than raising and aborting the apply."""
    calls = _fake_rndc(monkeypatch, rc=1, stderr="unknown command")
    driver = _driver(tmp_path, "options {\n    responselog yes;\n};\n")
    driver._sync_logging_runtime(["rndc"])  # must not raise
    assert len(calls) == 2, "a failed querylog must not stop the responselog call"
