"""firstboot's heredocs must never run their own text (#1132).

``_render_control_helmchart`` writes the spatium-control HelmChart through an
UNQUOTED here-document (``cat <<EOF``), so the shell expands everything inside
it: ``${chart_b64}`` and the other values on purpose, and any backtick pair as
well. The #1042 comment in that heredoc wrapped ten words in single backticks.
``/bin/sh`` (dash on the appliance) ran each one as a command substitution, as
root, on every boot. That left ten ``spatiumddi-firstboot: 1: <word>: not found``
lines per boot in /var/log/spatiumddi/firstboot.log, and the comment reached the
live HelmChart with those words deleted.

The renderer tests in test_firstboot_pod_posture.py and
test_secret_key_survives_reinstall.py run the function under bash and read
only its stdout, so they could not see this. The first two tests here run it
under dash, the shell the appliance uses, and read stderr as well. The third
scans every unquoted heredoc in the script, so the defect cannot come back in
another one.

``double backticks`` are the RST-style convention the script's comments
already use, and they are harmless: each pair is an empty command substitution
and runs nothing. The scan allows them. It refuses a backtick pair with
anything inside it.

HOW TO RUN (from the repo root or this directory):
    python3 -m pytest appliance/tests/test_firstboot_heredoc_backticks.py -v
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

SCRIPT = (
    Path(__file__).parent.parent
    / "mkosi.extra"
    / "usr"
    / "local"
    / "bin"
    / "spatiumddi-firstboot"
)

DASH = shutil.which("dash")
needs_dash = pytest.mark.skipif(
    DASH is None,
    reason="dash is the appliance's /bin/sh; measuring bash here would test another shell",
)

# The one line the renderer writes to stderr by design (>&2 — its stdout is the
# manifest), in whichever form this host's /proc/meminfo allows.
_SIZING = ("Sizing control plane for ", "MemTotal unreadable")


def _extract_function(name: str) -> str:
    """Return the shell source of a top-level ``name() { ... }`` function.

    Brace-matched from the opening line to a closing ``}`` at column 0, which is
    how every function in this script is written. Fails loudly if the name is
    gone, so a rename is an error rather than a vacuously passing test.
    """
    lines = SCRIPT.read_text(encoding="utf-8").splitlines()
    opener = f"{name}() {{"
    for i, line in enumerate(lines):
        if line == opener:
            break
    else:  # pragma: no cover - the assert below is the real reporter
        raise AssertionError(f"{name}() not found in {SCRIPT} (renamed?)")
    for j in range(i + 1, len(lines)):
        if lines[j] == "}":
            return "\n".join(lines[i : j + 1])
    raise AssertionError(f"{name}() has no closing brace at column 0")


def _render_under_dash() -> subprocess.CompletedProcess:
    body = _extract_function("_render_control_helmchart")
    return subprocess.run(
        [DASH, "-c", f'{body}\n_render_control_helmchart "Y2hhcnQ="\n'],
        env={
            **os.environ,
            "CHART_TGZ": "/nonexistent/appliance.tgz",
            "SPATIUMDDI_VERSION": "0.0.0-test",
        },
        capture_output=True,
        text=True,
        check=False,
    )


# ── the control HelmChart, rendered the way the appliance renders it ─────────


@needs_dash
def test_rendering_the_control_helmchart_reports_no_shell_error() -> None:
    proc = _render_under_dash()
    assert proc.returncode == 0, proc.stderr
    noise = [ln for ln in proc.stderr.splitlines() if not ln.startswith(_SIZING)]
    assert noise == [], (
        "dash reported errors while rendering the control HelmChart. Its heredoc "
        "is unquoted, so a backtick pair inside it is a command substitution that "
        f"runs on every boot, as root: {noise}"
    )


def _spec_level_comment() -> list[str]:
    """The comment lines the heredoc carries at HelmChart ``spec`` level, above
    ``valuesContent``. YAML drops them, so the parsed object never sees them, but
    the manifest k3s applies carries them as the record of why the chart is set
    the way it is (#1042)."""
    body = _extract_function("_render_control_helmchart")
    m = re.search(r"cat <<EOF\n(.*?)\nEOF\n", body, re.S)
    assert m, "_render_control_helmchart no longer renders through `cat <<EOF`"
    head = m.group(1).split("\n  valuesContent: |", 1)[0]
    return [ln for ln in head.splitlines() if ln.lstrip().startswith("#")]


@needs_dash
def test_the_spec_level_comment_reaches_the_manifest_verbatim() -> None:
    comment = _spec_level_comment()
    assert comment, (
        "no comment is left above valuesContent, so this test guards nothing; "
        "point it at whatever replaced the #1042 note"
    )
    proc = _render_under_dash()
    assert proc.returncode == 0, proc.stderr
    rendered = proc.stdout.splitlines()
    lost = [ln for ln in comment if ln not in rendered]
    assert lost == [], f"these comment lines did not render as written: {lost}"
    assert "\n".join(comment) in proc.stdout


# ── the whole script: no unquoted heredoc runs a backtick substitution ───────

# `<<WORD`, `<<-WORD`, `<<'WORD'`, `<<"WORD"`, `<<\WORD`; never a here-string's `<<<`.
_HEREDOC_OP = re.compile(r"(?<!<)<<(-?)[ \t]*(\\?)(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\3")


def _nonempty_backticks(body: str, first_line: int) -> list[tuple[int, str]]:
    """[(line, command)] for each backtick pair in an unquoted heredoc body that
    has anything inside it. A backslash escapes `` ` ``, ``$`` and ``\\`` there,
    exactly as the shell reads it."""
    found: list[tuple[int, str]] = []
    k, opened = 0, None
    while k < len(body):
        c = body[k]
        if c == "\\" and k + 1 < len(body) and body[k + 1] in "`$\\\n":
            k += 2
            continue
        if c == "`":
            if opened is None:
                opened = k
            else:
                inner = body[opened + 1 : k]
                if inner.strip():
                    found.append((first_line + body.count("\n", 0, opened), inner))
                opened = None
        k += 1
    if opened is not None:  # unterminated: dash would refuse the whole script
        found.append((first_line + body.count("\n", 0, opened), body[opened + 1 :]))
    return found


def backtick_substitutions(text: str) -> list[tuple[int, str]]:
    """[(line, command)] for every non-empty backtick command substitution inside
    an UNQUOTED here-document of the shell source ``text``, with 1-based line
    numbers. A quoted delimiter (``<<'EOF'``, ``<<"EOF"``, ``<<\\EOF``) keeps its
    body literal and is skipped."""
    lines = text.split("\n")
    found: list[tuple[int, str]] = []
    i = 0
    while i < len(lines):
        line = lines[i]
        i += 1
        if line.lstrip().startswith("#"):
            continue
        for m in _HEREDOC_OP.finditer(line):
            strip_tabs, backslash, quote, word = m.groups()
            start = i
            while i < len(lines) and (lines[i].lstrip("\t") if strip_tabs else lines[i]) != word:
                i += 1
            body = "\n".join(lines[start:i])
            i += 1  # past the terminator
            if not (quote or backslash):
                found += _nonempty_backticks(body, start + 1)
    return found


def test_no_unquoted_heredoc_in_firstboot_runs_a_backtick_substitution() -> None:
    found = backtick_substitutions(SCRIPT.read_text(encoding="utf-8"))
    assert found == [], (
        "a backtick pair inside an unquoted heredoc is a command substitution the "
        "shell runs on every boot, as root. Quote the word ('like this') or escape "
        "the backticks: " + "; ".join(f"line {n}: `{cmd}`" for n, cmd in found)
    )


def test_the_scan_can_fail() -> None:
    """Negative control: the scan above must see the #1132 shape and nothing
    else, or it is decoration."""
    sample = "\n".join(
        [
            "render() {",  # 1
            "    cat <<EOF",  # 2
            "  # left at the CRD default (`reinstall`) on purpose",  # 3
            "  # ``double`` backticks are empty substitutions and run nothing",  # 4
            "  # an escaped \\`word\\` is literal",  # 5
            "  value: ${x}",  # 6
            "EOF",  # 7
            "    cat <<'EOF'",  # 8
            "  # a quoted delimiter keeps `this` literal",  # 9
            "EOF",  # 10
            "    cat <<-EOT",  # 11
            "\t# a tab-stripped body still runs `this`",  # 12
            "\tEOT",  # 13
            '    x=$(cat <<<"`not a heredoc`")',  # 14
            "}",  # 15
        ]
    )
    assert backtick_substitutions(sample) == [(3, "reinstall"), (12, "this")]
