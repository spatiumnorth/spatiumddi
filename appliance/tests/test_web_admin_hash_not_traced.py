"""The web admin password hash never reaches the xtrace log (#4548).

spatium-install runs under ``set -x`` with BASH_XTRACEFD on a log that is
copied to the installed node (0644). xtrace prints every test with its value
expanded, so ``[ -n "$WEB_ADMIN_PASSWORD_HASH" ]`` wrote the full bcrypt hash
into the log. Only the write sat inside a tracing-off block.

The fix: everything else reads the non-secret ``WEB_ADMIN_PASSWORD_SET`` flag.
This guard checks the class: any expansion of the hash must sit in a
tracing-off region, and the tracing-on restore must not force ``-x``.
"""

from __future__ import annotations

import re
import subprocess

from _installer_source import SRC, extract_fn

FAKE = "$2b$12$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ01234"
EXPAND = re.compile(r"\$\{?WEB_ADMIN_PASSWORD_HASH\b")


def _lines():
    return SRC.splitlines()


def test_every_hash_expansion_is_traced_off():
    lines = _lines()
    ask = extract_fn("_ask_web_admin_password")
    bad = []
    for i, ln in enumerate(lines):
        code = ln.split("#", 1)[0]
        if not EXPAND.search(code) or code in ask:
            continue
        if "set +x" in "\n".join(lines[max(0, i - 8) : i + 1]):
            continue
        bad.append(f"{i + 1}: {ln.strip()}")
    assert not bad, "hash expanded while tracing may be on:\n" + "\n".join(bad)


def test_flag_exists_and_restore_does_not_force_trace():
    assert re.search(r'^WEB_ADMIN_PASSWORD_SET="no"', SRC, re.M)
    # a tracing-off block around the hash must put tracing back as it was
    for m in re.finditer(r"set \+x[^\n]*\n[^\n]*\n?[^\n]*WEB_ADMIN_PASSWORD_HASH", SRC):
        tail = SRC[m.end() : m.end() + 200]
        assert "_xtrace_was" in SRC[m.start() - 80 : m.end() + 200] or "set -x" not in tail


def test_ask_function_trace_has_no_hash():
    fn = extract_fn("_ask_web_admin_password")
    script = (
        "BACKTITLE=t HOSTNAME=h ROLE=control\n"
        "log() { :; }\nwhiptail() { return 0; }\n"
        f"_hash_web_password() {{ cat >/dev/null; printf '%s' '{FAKE}'; }}\n"
        "WEB_ADMIN_PASSWORD_HASH=''\nWEB_ADMIN_PASSWORD_SET=no\n"
        f"{fn}\n"
        "exec 19>\"$T\"; BASH_XTRACEFD=19; PS4='+ '\n"
        "{ set +x; } 2>/dev/null\n"  # the caller holds tracing off, as the wizard does
        "_ask_web_admin_password pw\n"
        "set -x\n"
        '[ "$WEB_ADMIN_PASSWORD_SET" = yes ] || exit 3\n'
        "set +x\n"
    )
    import os
    import tempfile

    with tempfile.TemporaryDirectory() as d:
        t = os.path.join(d, "trace")
        r = subprocess.run(
            ["bash", "-c", "set +x; " + script.replace("exec 19", "set -x; exec 19", 1)],
            env={**os.environ, "T": t},
            capture_output=True,
            text=True,
        )
        assert r.returncode == 0, r.stderr
        trace = open(t).read()
    assert "$2b$" not in trace and "abcdefghij" not in trace
