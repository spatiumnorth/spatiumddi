"""firstboot keeps SECRET_KEY in a Secret Helm does not own (#1448).

The control chart's own ``spatium-control-spatiumddi-app`` Secret is deleted
by a helm uninstall unless the STORED release manifest marks it ``keep``, and
2026.09.04-1's does not. On the first upgrade from that release, a failed
first install on the new slot made helm-controller uninstall with the old
manifest, delete the Secret, and mint a new key on the reinstall: every
credential encrypted at rest became unreadable (#1445).

``ensure_app_key_secret`` copies the key into ``spatium-control-app-keys`` —
no Helm ownership — before the control chart that points at it is released.
These tests drive the real function against a stub ``k3s`` that plays the
apiserver, so every guard runs as a shell, not reasoned about:

  * an upgrade copies ``secret-key`` byte for byte, and generates the
    ``metrics-token`` 2026.09.04-1's Secret does not carry;
  * a fresh install, with neither Secret, generates both;
  * an existing ``spatium-control-app-keys`` is never overwritten;
  * the chart's Secret present WITHOUT a key is refused, never filled with a
    generated one (that would be the bug again);
  * an apiserver that does not answer → non-zero, nothing created, no stamp;
  * a read-back that disagrees with the source key → non-zero, no stamp.

And the half that makes failure safe: the rendered control HelmChart carries
``auth.existingSecret`` on marker lines, and ``_strip_control_app_secret``
removes exactly those lines, leaving the chart managing its own Secret as
before.

It runs under ``sh`` (dash on the appliance and on the CI runner) so a bashism
fails here rather than on a boot. The strip uses GNU ``sed -i``, so it needs a
GNU sed — the appliance's and the CI runner's.

HOW TO RUN (from the repo root or this directory):
    python3 -m pytest appliance/tests/test_firstboot_app_key_secret.py -v
"""

from __future__ import annotations

import base64
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
FUNC = "ensure_app_key_secret"
SHELL = shutil.which("dash") or "sh"

APP_KEYS = "spatium-control-app-keys"
CHART_APP = "spatium-control-spatiumddi-app"
MARKER = "# spatium:app-key-secret"

# The stub apiserver. Each Secret is a directory under $STUB/secrets/<name>
# holding one file per data key (base64 value, as the apiserver returns it).
# ``apierr`` = the apiserver is down; ``createfail`` = ``create`` fails without
# creating anything; ``tamper`` = ``create`` stores a different secret-key than
# it was sent (to prove the read-back is a real check).
STUB_K3S = r"""#!/bin/sh
S="$STUB"
echo "$*" >> "$S/calls.log"
[ "$1" = kubectl ] && shift
[ -f "$S/apierr" ] && { echo "The connection to the server 127.0.0.1:6443 was refused" >&2; exit 1; }
case "$*" in
  "-n spatium get secret "*" --ignore-not-found -o name")
    name=$5
    [ -d "$S/secrets/$name" ] && echo "secret/$name"
    exit 0 ;;
  "-n spatium get secret "*" -o jsonpath={.metadata.resourceVersion} {.data.credential-key}")
    name=$5
    [ -d "$S/secrets/$name" ] || exit 1
    rv=1; [ -f "$S/secrets/$name/.rv" ] && rv=$(cat "$S/secrets/$name/.rv")
    ck=""; [ -f "$S/secrets/$name/credential-key" ] && ck=$(cat "$S/secrets/$name/credential-key")
    printf '%s %s' "$rv" "$ck"
    exit 0 ;;
  "-n spatium get secret "*" -o jsonpath="*)
    name=$5
    [ -d "$S/secrets/$name" ] || { echo "Error from server (NotFound): secrets \"$name\" not found" >&2; exit 1; }
    case "$*" in
      *"{.data.secret-key}"*) f=secret-key ;;
      *"{.data.metrics-token}"*) f=metrics-token ;;
      *"{.data.credential-key}"*) f=credential-key ;;
      *"{.data.credential-key-since}"*) f=credential-key-since ;;
      *) echo "stub: unexpected jsonpath: $*" >&2; exit 3 ;;
    esac
    [ -f "$S/secrets/$name/$f" ] && printf '%s' "$(cat "$S/secrets/$name/$f")"
    exit 0 ;;
  "-n spatium create -f -")
    cat > "$S/created.yaml"
    [ -f "$S/createfail" ] && { echo "stub: create refused" >&2; exit 1; }
    name=$(sed -n 's/^  name: //p' "$S/created.yaml")
    [ -d "$S/secrets/$name" ] && { echo "AlreadyExists" >&2; exit 1; }
    mkdir -p "$S/secrets/$name"
    for f in secret-key metrics-token credential-key credential-key-since; do
      v=$(sed -n "s/^  $f: //p" "$S/created.yaml" | tr -d '\n')
      [ -n "$v" ] && printf '%s' "$v" > "$S/secrets/$name/$f"
    done
    [ -f "$S/tamper" ] && printf 'dGFtcGVyZWQ=' > "$S/secrets/$name/secret-key"
    exit 0 ;;
  "-n spatium patch secret "*" --type merge --patch-file /dev/stdin")
    name=$5
    [ -d "$S/secrets/$name" ] || exit 1
    [ -f "$S/patchfail" ] && { echo "stub: patch refused" >&2; exit 1; }
    cat > "$S/patch.json"
    # The apiserver's optimistic lock: a stale resourceVersion is a 409.
    rv=1; [ -f "$S/secrets/$name/.rv" ] && rv=$(cat "$S/secrets/$name/.rv")
    [ -f "$S/bumprv" ] && rv=$((rv + 1))
    grep -q "\"resourceVersion\":\"$rv\"" "$S/patch.json" || { echo "Conflict (409)" >&2; exit 1; }
    sed -n 's/.*"credential-key":"\([^"]*\)".*/\1/p' "$S/patch.json" | tr -d '\n' > "$S/secrets/$name/credential-key"
    sed -n 's/.*"credential-key-since":"\([^"]*\)".*/\1/p' "$S/patch.json" | tr -d '\n' > "$S/secrets/$name/credential-key-since"
    exit 0 ;;
esac
echo "stub k3s: unexpected: $*" >&2
exit 3
"""


def _extract_function(name: str) -> str:
    """The shell source of a top-level ``name() { ... }`` (closing brace at column 0)."""
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


def _b64(s: str) -> str:
    return base64.b64encode(s.encode()).decode()


class Run:
    def __init__(self, proc: subprocess.CompletedProcess, stub: Path, stamp: Path):
        self.proc = proc
        self.stub = stub
        self.stamp = stamp

    def secret(self, name: str) -> dict[str, str] | None:
        d = self.stub / "secrets" / name
        if not d.is_dir():
            return None
        return {f.name: f.read_text() for f in d.iterdir() if not f.name.startswith(".")}

    @property
    def created(self) -> str | None:
        p = self.stub / "created.yaml"
        return p.read_text() if p.exists() else None


def _run(tmp_path: Path, *, secrets: dict[str, dict[str, str]] | None = None,
         apierr: bool = False, createfail: bool = False, tamper: bool = False,
         patchfail: bool = False, bumprv: bool = False,
         version: str | None = "2026.11.13-1") -> Run:
    stub = tmp_path / "stub"
    stub.mkdir()
    (stub / "secrets").mkdir()
    for name, data in (secrets or {}).items():
        d = stub / "secrets" / name
        d.mkdir()
        for k, v in data.items():
            (d / k).write_text(v)
    for flag, on in (("apierr", apierr), ("createfail", createfail), ("tamper", tamper),
                     ("patchfail", patchfail), ("bumprv", bumprv)):
        if on:
            (stub / flag).touch()
    k3s = tmp_path / "k3s"
    k3s.write_text(STUB_K3S)
    k3s.chmod(0o755)
    stamp = tmp_path / "app-key-secret.done"
    body = "\n".join(
        _extract_function(f) for f in ("_new_credential_key_b64", "ensure_credential_key", FUNC)
    ).replace("/usr/local/bin/k3s", str(k3s))
    script = (
        "set -eu\n"                              # what the shipped script runs under
        f'. "{SCRIPT}"\n'                        # the lib half: constants
        f'APP_KEY_STAMP="{stamp}"\n'
        f"{body}\n"
        f"{FUNC}\n"
    )
    proc = subprocess.run(
        [SHELL, "-c", script],
        env={
            **{k: v for k, v in os.environ.items() if k != "SPATIUMDDI_VERSION"},
            "SPATIUM_FIRSTBOOT_LIB": "1",
            "STUB": str(stub),
            **({"SPATIUMDDI_VERSION": version} if version is not None else {}),
        },
        capture_output=True,
        text=True,
        check=False,
    )
    return Run(proc, stub, stamp)


def test_the_constants_name_the_secrets_the_chart_reads():
    src = SCRIPT.read_text(encoding="utf-8")
    assert f"APP_KEY_SECRET={APP_KEYS}\n" in src
    # The chart's own Secret is ``<release>-spatiumddi-app``; the release is
    # spatium-control. A wrong name here would "find" nothing on every upgrade
    # and generate a NEW key — the exact failure this exists to prevent.
    assert f"CHART_APP_SECRET={CHART_APP}\n" in src


def test_upgrade_copies_the_key_byte_for_byte_and_generates_the_token(tmp_path):
    key = _b64("a" * 64)
    r = _run(tmp_path, secrets={CHART_APP: {"secret-key": key}})
    assert r.proc.returncode == 0, r.proc.stderr
    got = r.secret(APP_KEYS)
    assert got is not None
    assert got["secret-key"] == key
    token = base64.b64decode(got["metrics-token"]).decode()
    assert re.fullmatch(r"[0-9a-f]{48}", token), token
    assert r.stamp.exists()
    # The source is read, never touched.
    assert r.secret(CHART_APP) == {"secret-key": key}


def test_upgrade_keeps_an_existing_metrics_token(tmp_path):
    key, token = _b64("b" * 64), _b64("c" * 48)
    r = _run(tmp_path, secrets={CHART_APP: {"secret-key": key, "metrics-token": token}})
    assert r.proc.returncode == 0, r.proc.stderr
    got = r.secret(APP_KEYS)
    assert got is not None
    got.pop("credential-key")  # #1358: generated alongside; asserted below
    got.pop("credential-key-since")
    assert got == {"secret-key": key, "metrics-token": token}


def test_the_new_secret_carries_no_helm_ownership_and_the_console_label(tmp_path):
    r = _run(tmp_path, secrets={CHART_APP: {"secret-key": _b64("d" * 64)}})
    assert r.proc.returncode == 0, r.proc.stderr
    created = r.created
    assert created is not None
    # Helm adopts (and so may delete) an object carrying its ownership
    # metadata; this Secret must carry none.
    assert "meta.helm.sh" not in created
    assert "managed-by" not in created
    # The console finds the metrics token by this label.
    assert "app.kubernetes.io/name: spatiumddi" in created
    assert "namespace: spatium" in created


def test_fresh_install_generates_both_values(tmp_path):
    r = _run(tmp_path)
    assert r.proc.returncode == 0, r.proc.stderr
    got = r.secret(APP_KEYS)
    assert got is not None
    assert re.fullmatch(r"[0-9a-f]{64}", base64.b64decode(got["secret-key"]).decode())
    assert re.fullmatch(r"[0-9a-f]{48}", base64.b64decode(got["metrics-token"]).decode())
    assert r.stamp.exists()


def test_an_existing_app_keys_secret_is_never_overwritten(tmp_path):
    mine = {"secret-key": _b64("e" * 64), "metrics-token": _b64("f" * 48)}
    r = _run(tmp_path, secrets={APP_KEYS: dict(mine), CHART_APP: {"secret-key": _b64("0" * 64)}})
    assert r.proc.returncode == 0, r.proc.stderr
    got = r.secret(APP_KEYS)
    assert got is not None
    got.pop("credential-key")  # #1358: added when missing; the keys above are untouched
    got.pop("credential-key-since")
    assert got == mine
    assert r.created is None
    assert r.stamp.exists()


def test_chart_secret_without_a_key_is_refused_not_filled(tmp_path):
    r = _run(tmp_path, secrets={CHART_APP: {"metrics-token": _b64("1" * 48)}})
    assert r.proc.returncode != 0
    assert r.secret(APP_KEYS) is None
    assert r.created is None
    assert not r.stamp.exists()
    assert "carries no secret-key" in r.proc.stderr


def test_apiserver_down_creates_nothing_and_writes_no_stamp(tmp_path):
    r = _run(tmp_path, secrets={CHART_APP: {"secret-key": _b64("2" * 64)}}, apierr=True)
    assert r.proc.returncode != 0
    assert r.created is None
    assert not r.stamp.exists()


def test_a_failed_create_with_nothing_created_returns_non_zero(tmp_path):
    r = _run(tmp_path, secrets={CHART_APP: {"secret-key": _b64("3" * 64)}}, createfail=True)
    assert r.proc.returncode != 0
    assert r.secret(APP_KEYS) is None
    assert not r.stamp.exists()


def test_a_read_back_that_disagrees_is_a_failure(tmp_path):
    r = _run(tmp_path, secrets={CHART_APP: {"secret-key": _b64("4" * 64)}}, tamper=True)
    assert r.proc.returncode != 0
    assert not r.stamp.exists()
    assert "different secret-key" in r.proc.stderr


def test_values_never_reach_argv(tmp_path):
    key = _b64("5" * 64)
    r = _run(tmp_path, secrets={CHART_APP: {"secret-key": key}})
    assert r.proc.returncode == 0, r.proc.stderr
    calls = (r.stub / "calls.log").read_text()
    assert key not in calls
    assert r.secret(APP_KEYS)["metrics-token"] not in calls


# --- the marker lines and the strip ---------------------------------------


def _rendered_valuescontent_lines() -> list[str]:
    src = SCRIPT.read_text(encoding="utf-8")
    return [line for line in src.splitlines() if line.endswith(MARKER)]


def test_the_control_chart_points_at_the_app_keys_secret_on_marker_lines():
    lines = _rendered_valuescontent_lines()
    stripped = [line[: -len(MARKER)].rstrip() for line in lines]
    assert stripped == ["    auth:", '      existingSecret: "${APP_KEY_SECRET}"'], lines


@pytest.mark.skipif(
    subprocess.run(["sed", "--version"], capture_output=True).returncode != 0,
    reason="needs GNU sed (the appliance's); BSD sed -i takes a suffix",
)
def test_strip_removes_exactly_the_marker_lines(tmp_path):
    manifest = tmp_path / "spatium-control.yaml.deferred"
    original = (
        "  valuesContent: |\n"
        "    image:\n"
        '      tag: "2026.10.03-1"\n'
        f"    auth:  {MARKER}\n"
        f'      existingSecret: "{APP_KEYS}"  {MARKER}\n'
        "    # a comment that mentions spatium:app-key-secret mid-line stays\n"
        "    controlPlane:\n"
        "      nodeSelector: {}\n"
    )
    manifest.write_text(original)
    body = _extract_function("_strip_control_app_secret")
    proc = subprocess.run(
        [SHELL, "-c", f'{body}\n_strip_control_app_secret "{manifest}"'],
        capture_output=True, text=True, check=False,
    )
    assert proc.returncode == 0, proc.stderr
    want = "".join(
        line + "\n" for line in original.splitlines() if not line.endswith(MARKER)
    )
    assert manifest.read_text() == want
    assert "existingSecret" not in manifest.read_text()


def test_the_release_path_strips_when_the_secret_could_not_be_ensured():
    body = _extract_function("place_deferred_control_manifest")
    ensure = body.index("ensure_app_key_secret")
    strip = body.index('_strip_control_app_secret "$deferred"')
    release = body.index("release_control_manifest")
    # Ensure, strip on failure, THEN release: releasing first would apply a
    # chart naming a Secret that does not exist, and its pods would not start.
    assert ensure < strip < release
    assert "if ! ensure_app_key_secret" in body


def test_the_k3s_not_ready_path_strips_unless_the_stamp_says_the_secret_exists():
    src = SCRIPT.read_text(encoding="utf-8")
    guard = 'if [ -f "${CONTROL_MANIFEST}.deferred" ] && [ ! -f "$APP_KEY_STAMP" ]; then'
    assert guard in src
    after = src[src.index(guard):]
    assert after.index('_strip_control_app_secret "${CONTROL_MANIFEST}.deferred"') < after.index(
        "release_control_manifest"
    )


# ── #1358: the dedicated at-rest key rides in the same Secret ────────────────


def _is_fernet_key_b64(value: str) -> bool:
    """``value`` is the Secret's data field: base64 of a Fernet key, which is
    url-safe base64 of 32 bytes."""
    key = base64.b64decode(value).decode()
    return len(base64.urlsafe_b64decode(key)) == 32


def test_fresh_install_generates_a_credential_key(tmp_path):
    r = _run(tmp_path)
    assert r.proc.returncode == 0, r.proc.stderr
    got = r.secret(APP_KEYS)
    assert got is not None and _is_fernet_key_b64(got["credential-key"])


def test_upgrade_generates_a_credential_key_when_the_chart_secret_has_none(tmp_path):
    r = _run(tmp_path, secrets={CHART_APP: {"secret-key": _b64("a" * 64)}})
    got = r.secret(APP_KEYS)
    assert got is not None and _is_fernet_key_b64(got["credential-key"])


def test_upgrade_carries_over_a_credential_key_the_chart_already_minted(tmp_path):
    ckey = _b64("Zm9vYmFyZm9vYmFyZm9vYmFyZm9vYmFyZm9vYmFyZm8=")
    r = _run(
        tmp_path,
        secrets={CHART_APP: {"secret-key": _b64("a" * 64), "credential-key": ckey}},
    )
    got = r.secret(APP_KEYS)
    assert got is not None and got["credential-key"] == ckey


def test_an_existing_app_keys_secret_without_the_key_gets_one_added(tmp_path):
    key = _b64("a" * 64)
    r = _run(tmp_path, secrets={APP_KEYS: {"secret-key": key}})
    assert r.proc.returncode == 0, r.proc.stderr
    got = r.secret(APP_KEYS)
    assert got is not None and got["secret-key"] == key
    assert _is_fernet_key_b64(got["credential-key"])


def test_an_existing_credential_key_is_never_replaced(tmp_path):
    ckey = _b64("Zm9vYmFyZm9vYmFyZm9vYmFyZm9vYmFyZm9vYmFyZm8=")
    r = _run(
        tmp_path,
        secrets={APP_KEYS: {"secret-key": _b64("a" * 64), "credential-key": ckey}},
    )
    got = r.secret(APP_KEYS)
    assert got is not None and got["credential-key"] == ckey
    assert "patch" not in (r.stub / "calls.log").read_text()


def test_a_failed_credential_key_patch_does_not_fail_the_secret(tmp_path):
    """auth.existingSecret stays on secret-key alone; failing here would make
    the caller strip it and swap in a chart-owned SECRET_KEY."""
    r = _run(tmp_path, secrets={APP_KEYS: {"secret-key": _b64("a" * 64)}}, patchfail=True)
    assert r.proc.returncode == 0, r.proc.stderr
    assert r.stamp.exists()
    got = r.secret(APP_KEYS)
    assert got is not None and "credential-key" not in got


# ── #1358: no reader without the key ever sees a value written under it ──────


def test_a_key_added_to_a_running_install_is_stamped_with_this_version(tmp_path):
    r = _run(tmp_path, secrets={APP_KEYS: {"secret-key": _b64("a" * 64)}})
    assert r.proc.returncode == 0, r.proc.stderr
    got = r.secret(APP_KEYS)
    assert got is not None and _is_fernet_key_b64(got["credential-key"])
    # The api of this version reads it but keeps writing under the old key.
    assert base64.b64decode(got["credential-key-since"]).decode() == "2026.11.13-1"
    patch = (r.stub / "patch.json").read_text()
    assert '"resourceVersion":"1"' in patch


def test_no_key_is_added_when_the_version_is_unknown(tmp_path):
    r = _run(tmp_path, secrets={APP_KEYS: {"secret-key": _b64("a" * 64)}}, version=None)
    assert r.proc.returncode == 0, r.proc.stderr
    assert "credential-key" not in (r.secret(APP_KEYS) or {})


def test_a_second_node_racing_to_add_a_key_does_not_replace_the_first(tmp_path):
    # The Secret changed between our read and our patch (another node added
    # its key): the stale resourceVersion is refused and nothing is replaced.
    r = _run(tmp_path, secrets={APP_KEYS: {"secret-key": _b64("a" * 64)}}, bumprv=True)
    assert r.proc.returncode == 0, r.proc.stderr
    got = r.secret(APP_KEYS)
    assert got is not None and "credential-key" not in got
    assert "another node" in r.proc.stderr


def test_a_fresh_install_key_carries_no_stamp(tmp_path):
    r = _run(tmp_path)
    got = r.secret(APP_KEYS)
    assert got is not None and "credential-key-since" not in got


def test_a_key_generated_for_a_chart_owned_install_is_stamped(tmp_path):
    r = _run(tmp_path, secrets={CHART_APP: {"secret-key": _b64("a" * 64)}})
    got = r.secret(APP_KEYS)
    assert got is not None
    assert base64.b64decode(got["credential-key-since"]).decode() == "2026.11.13-1"


def test_the_chart_minted_stamp_is_carried_over(tmp_path):
    ckey = _b64("Zm9vYmFyZm9vYmFyZm9vYmFyZm9vYmFyZm9vYmFyZm8=")
    r = _run(
        tmp_path,
        secrets={
            CHART_APP: {
                "secret-key": _b64("a" * 64),
                "credential-key": ckey,
                "credential-key-since": _b64("2026.11.01-1"),
            }
        },
    )
    got = r.secret(APP_KEYS)
    assert got is not None and got["credential-key"] == ckey
    assert base64.b64decode(got["credential-key-since"]).decode() == "2026.11.01-1"
