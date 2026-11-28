"""The appliance web UI starts on the password the installer collected (#4548).

The installer asked for an OS password and the web UI still started on the
built-in admin / admin, so whoever reached :443 first set the real one. The
chain under test: installer hashes (bcrypt) -> STATE file -> firstboot puts it
in the app Secret -> api seeds the first user with it. Each hop is exercised
by running the real shell / python, with the cluster and disks stubbed.

    python3 -m pytest appliance/tests/test_web_admin_password_4548.py -v
"""

from __future__ import annotations

import base64
import os
import re
import subprocess
from pathlib import Path

import pytest

from _installer_source import BIN, INSTALLER, SRC, extract_fn

FIRSTBOOT = BIN / "spatiumddi-firstboot"
ETC_RENDER = BIN / "spatium-etc-render"
PARSER = BIN / "spatium-preseed-parse"
ISSUE = BIN.parents[2] / "etc" / "issue"

# A syntactically valid bcrypt hash (cost 4, throwaway).
GOOD_HASH = "$2b$04$" + "a" * 53
SECRET_WORD = "Sup3r-secret-web-pw"


def _sh(script: str, **kw) -> subprocess.CompletedProcess:
    return subprocess.run(["bash", "-c", script], capture_output=True, text=True, **kw)


# ── preseed ──────────────────────────────────────────────────────────────────


def _parse(tmp_path: Path, body: str) -> tuple[int, str, str, str]:
    conf = tmp_path / "p.yaml"
    conf.write_text("spatium_preseed:\n  role: control-plane\n  hostname: cp1\n" + body)
    env, sec = tmp_path / "env", tmp_path / "secret"
    r = subprocess.run(
        ["python3", str(PARSER), str(conf), str(env), str(sec)], capture_output=True, text=True
    )
    return (
        r.returncode,
        env.read_text() if env.exists() else "",
        sec.read_text() if sec.exists() else "",
        r.stdout + r.stderr,
    )


def test_preseed_hash_lands_in_the_secret_file_only(tmp_path: Path) -> None:
    rc, env, sec, out = _parse(tmp_path, f'  web_admin_password_hash: "{GOOD_HASH}"\n')
    assert rc == 0, out
    assert "WEB_ADMIN_PASSWORD_HASH" in sec and GOOD_HASH in sec
    assert "PRESEED_HAS_WEB_ADMIN_PASSWORD=1" in env
    assert GOOD_HASH not in env and GOOD_HASH not in out


def test_preseed_rejects_a_value_that_is_not_a_bcrypt_hash(tmp_path: Path) -> None:
    for bad in (SECRET_WORD, "$6$salt$hash", "$2b$04$short"):
        rc, _env, sec, out = _parse(tmp_path, f'  web_admin_password_hash: "{bad}"\n')
        assert rc == 2, out
        assert "web_admin_password_hash" in out
        assert "WEB_ADMIN_PASSWORD_HASH" not in sec


def test_preseed_has_no_plaintext_key(tmp_path: Path) -> None:
    rc, env, sec, _out = _parse(tmp_path, f'  web_admin_password: "{SECRET_WORD}"\n')
    assert SECRET_WORD not in env + sec
    assert "WEB_ADMIN" not in env + sec


def test_preseed_without_it_is_unchanged(tmp_path: Path) -> None:
    rc, env, sec, out = _parse(tmp_path, "")
    assert rc == 0, out
    assert "WEB_ADMIN" not in env + sec


def _lint(tmp_path: Path, role_block: str, extra: str) -> str:
    conf = tmp_path / "ps.yaml"
    conf.write_text(
        f"spatium_preseed:\n{role_block}  hostname: cp1\n  admin_password: 'ChangeMe!12345'\n"
        f"  network:\n    mode: dhcp\n{extra}"
    )
    env = {
        "PATH": os.environ["PATH"],
        "SPATIUM_INSTALL_LOG": str(tmp_path / "i.log"),
        "SPATIUM_INSTALL_TRACE_LOG": str(tmp_path / "t.log"),
        "HOME": str(tmp_path),
        # the linter's HOME is the tmp dir; keep the test run's user site
        "PYTHONUSERBASE": os.path.expanduser("~/.local"),
    }
    r = subprocess.run(
        ["bash", str(INSTALLER), "--check-preseed", str(conf)],
        capture_output=True,
        text=True,
        env=env,
        timeout=60,
    )
    return r.stdout + r.stderr


def test_check_preseed_reports_the_web_ui_login(tmp_path: Path) -> None:
    cp = "  role: control-plane\n"
    with_hash = _lint(tmp_path, cp, f'  web_admin_password_hash: "{GOOD_HASH}"\n')
    assert "web UI admin password: set from web_admin_password_hash" in with_hash
    assert GOOD_HASH not in with_hash
    without = _lint(tmp_path, cp, "")
    assert "web UI admin password: not in the file" in without


# ── installer ────────────────────────────────────────────────────────────────


def test_installer_hash_is_bcrypt_and_matches(tmp_path: Path) -> None:
    bcrypt = pytest.importorskip("bcrypt")
    fn = extract_fn("_hash_web_password")
    r = _sh(f'INSTALL_LOG={tmp_path}/log\n{fn}\nprintf %s {SECRET_WORD} | _hash_web_password')
    assert r.returncode == 0, r.stderr
    assert bcrypt.checkpw(SECRET_WORD.encode(), r.stdout.encode())
    assert SECRET_WORD not in r.stdout


def test_installer_writes_the_hash_to_state_0600_and_never_the_export() -> None:
    # The hash file is written with tracing off and a 077 umask ...
    block = SRC[SRC.index('rm -f "$STATE_MNT/web-admin-password-hash"') :][:600]
    assert "set +x" in block and "umask 077" in block
    # ... and the exported answers file never names it with a value.
    export = SRC[SRC.index('cat > "$STATE_MNT/spatium-preseed.yaml"') :][:2500]
    assert "WEB_ADMIN_PASSWORD_HASH" not in export
    assert "web_admin_password_hash:" not in export


def test_installer_never_logs_the_hash() -> None:
    for ln in SRC.splitlines():
        if "WEB_ADMIN_PASSWORD_HASH" in ln and re.search(r"\b(log|echo)\b", ln):
            assert "$WEB_ADMIN_PASSWORD_HASH" not in ln.split("log", 1)[-1] or "[ -n" in ln, ln


def test_done_screen_names_the_chosen_login() -> None:
    assert "the web UI password you set in this installer" in SRC
    assert 'Login:   admin / admin  (change forced on first login)"' in SRC  # the default kept


# ── firstboot ────────────────────────────────────────────────────────────────

_KUBECTL = r"""#!/bin/bash
# Minimal kubectl stub: remembers what `create -f -` was given.
d="$(dirname "$0")"
case "$*" in
  *"create -f -"*) cat > "$d/created.yaml" ;;
  *"get secret spatium-control-app-keys --ignore-not-found"*)
      [ -f "$d/created.yaml" ] && echo secret/spatium-control-app-keys ;;
  *"jsonpath={.data.secret-key}"*) sed -n 's/^  secret-key: //p' "$d/created.yaml" ;;
esac
exit 0
"""


def _run_ensure(tmp_path: Path, hash_text: str | None) -> str:
    src = FIRSTBOOT.read_text(encoding="utf-8")
    fns = "\n".join(
        extract_fn(n, src)
        for n in ("_new_credential_key_b64", "ensure_credential_key", "ensure_app_key_secret")
    )
    kube = tmp_path / "kubectl"
    kube.write_text(_KUBECTL)
    kube.chmod(0o755)
    hf = tmp_path / "web-admin-password-hash"
    if hash_text is not None:
        hf.write_text(hash_text + "\n")
    fns = fns.replace('"/usr/local/bin/k3s kubectl -n spatium"', f'"{kube} -n spatium"')
    r = _sh(
        f"""set -u
APP_KEY_SECRET=spatium-control-app-keys
CHART_APP_SECRET=spatium-control-spatiumddi-app
APP_KEY_STAMP={tmp_path}/stamp
WEB_ADMIN_HASH_FILE={hf}
SPATIUMDDI_VERSION=0.0.0-test
{fns}
ensure_app_key_secret"""
    )
    assert r.returncode == 0, r.stderr
    return (tmp_path / "created.yaml").read_text()


def test_firstboot_hands_the_hash_to_the_app_secret(tmp_path: Path) -> None:
    created = _run_ensure(tmp_path, GOOD_HASH)
    m = re.search(r"^  initial-admin-password-hash: (\S+)$", created, re.M)
    assert m, created
    assert base64.b64decode(m.group(1)).decode() == GOOD_HASH


def test_firstboot_without_a_hash_adds_no_key(tmp_path: Path) -> None:
    created = _run_ensure(tmp_path, None)
    assert "initial-admin-password-hash" not in created
    assert "secret-key:" in created


# ── /etc/issue ───────────────────────────────────────────────────────────────


def _render_issue(tmp_path: Path, role: str, web_set: str) -> str:
    src = ETC_RENDER.read_text(encoding="utf-8")
    start = src.index("ISSUE_BASE=")
    block = src[start : src.index("\nfi\n", start) + 4]
    block = block.replace("/etc/issue", str(tmp_path / "issue"))
    block = block.replace("ISSUE_BASE=/usr/lib/etc.image/issue", f"ISSUE_BASE={ISSUE}")
    r = _sh(
        f"""get_cfg() {{ [ "$1" = web_admin_password_set ] && echo '{web_set}'; return 0; }}
ROLE_VAL='{role}'
{block}"""
    )
    assert r.returncode == 0, r.stderr
    return (tmp_path / "issue").read_text()


def test_issue_for_a_first_node_with_a_chosen_password(tmp_path: Path) -> None:
    out = _render_issue(tmp_path, "control-plane", "yes")
    assert "admin / admin" not in out
    assert "password you set at install" in out and "Web UI:" in out


def test_issue_for_a_first_node_on_the_default_is_unchanged(tmp_path: Path) -> None:
    assert _render_issue(tmp_path, "control-plane", "no") == ISSUE.read_text()


def test_issue_for_an_additional_node_has_no_web_ui_lines(tmp_path: Path) -> None:
    out = _render_issue(tmp_path, "appliance", "no")
    assert "Web UI" not in out and "admin / admin" not in out
    assert "SSH login" in out
