"""``python3 -`` host runners must not expect their data on stdin (#1001).

``python3 -`` means *read the program from stdin*.  A host runner written as::

    printf '%s' "$JSON" | python3 - "$ARG" <<'PYEOF'
    ...  json.load(sys.stdin)  ...
    PYEOF

therefore has the pipe and the heredoc both claiming fd 0.  Redirections are
applied left to right, so under bash the heredoc — the later one — wins
outright: python gets the right *program* and ``sys.stdin`` is the heredoc,
already consumed to EOF by the parser.  The piped data is silently discarded.

Three runners shipped that way, and the blast radius was decided entirely by
whichever ``except`` clause each site happened to have:

* ``spatiumddi-ssh-reload``   — failed **OPEN**: the source-CIDR allowlist was
  discarded, the empty-list branch rendered an unscoped ``accept``, and the
  nft dry-run, the applied sidecar and the Fleet UI all reported success.
* ``spatiumddi-syslog-reload`` — failed closed and loudly; TLS syslog with an
  operator-supplied CA had never worked.
* ``spatiumddi-image-prune``  — silently inert; nothing was ever pruned.

Two of the three swallowed the exception, so the guard has to assert on the
**rendered artefact**, not on an exit code (the #899 lesson: assert on the
rendered config, not the stored row).  These tests extract the real command
line + heredoc out of the shipped script and run it under bash, so they are
testing the bytes that ship rather than a transcription of them.

HOW TO RUN (from the repo root or this directory):
    python3 -m pytest appliance/tests/test_host_runner_stdin_programs.py -v

No database, no Docker, no appliance ISO, no root required.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
from pathlib import Path

import pytest

BIN = Path(__file__).parent.parent / "mkosi.extra" / "usr" / "local" / "bin"

SSH_RELOAD = BIN / "spatiumddi-ssh-reload"
SYSLOG_RELOAD = BIN / "spatiumddi-syslog-reload"
IMAGE_PRUNE = BIN / "spatiumddi-image-prune"


# --------------------------------------------------------------------------
# extracting the real snippet out of the real script
# --------------------------------------------------------------------------
def _extract_heredoc_command(script: Path, marker: str) -> str:
    """Return the bash snippet from the line containing ``marker`` through the
    line that closes its heredoc.

    The heredoc bodies in these runners sit at column 0 with the terminator at
    column 0, so the extracted text is a runnable bash command as-is.  A
    leading ``if ! `` is stripped: callers re-wrap it themselves so the
    negation semantics stay explicit in the test.
    """
    lines = script.read_text(encoding="utf-8").splitlines()
    starts = [i for i, ln in enumerate(lines) if marker in ln]
    assert len(starts) == 1, f"{marker!r} found {len(starts)}x in {script.name}"
    start = starts[0]

    opener = re.search(r"<<-?'?([A-Za-z_][A-Za-z0-9_]*)'?\s*$", lines[start])
    assert opener, f"no heredoc opener on {script.name}:{start + 1}: {lines[start]!r}"
    delim = opener.group(1)

    end = next(
        (i for i in range(start + 1, len(lines)) if lines[i].strip() == delim),
        None,
    )
    assert end is not None, f"unterminated heredoc {delim} in {script.name}"

    body = list(lines[start : end + 1])
    body[0] = re.sub(r"^\s*if\s+!\s+", "", body[0])
    return "\n".join(body)


def _run(snippet: str, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    """Run an extracted snippet under **bash** (never zsh — see module docs).

    ``PATH`` is inherited rather than pinned: python3 lives somewhere
    different on a developer mac, a python:slim image and a setup-python
    runner, and a hardcoded list silently turns every case into a 127.
    """
    return subprocess.run(
        ["bash", "-euo", "pipefail", "-c", snippet],
        capture_output=True,
        text=True,
        env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), **env},
    )


# --------------------------------------------------------------------------
# 1. spatiumddi-ssh-reload — the allowlist must reach the rendered rule
# --------------------------------------------------------------------------
SSH_MARKER = 'python3 - "$PORT" "$CIDR_JSON"'


def _render_ssh(cidr_json: str, port: str = "22") -> subprocess.CompletedProcess[str]:
    snippet = _extract_heredoc_command(SSH_RELOAD, SSH_MARKER)
    return _run(snippet, {"PORT": port, "CIDR_JSON": cidr_json, "NFT_TMP": "/dev/stdout"})


def test_ssh_allowlist_reaches_the_rendered_rule() -> None:
    """The property that was missing: ``ip saddr`` present, with both CIDRs.

    This is the whole bug.  Before #1001 this rendered
    ``tcp dport 22 accept`` — valid nftables, passes ``nft -c``, opens the
    port to the entire internet.
    """
    res = _render_ssh('["10.0.0.0/8","192.168.1.0/24"]')
    assert res.returncode == 0, res.stderr
    assert "ip saddr" in res.stdout, f"allowlist was discarded:\n{res.stdout}"
    assert "10.0.0.0/8" in res.stdout
    assert "192.168.1.0/24" in res.stdout
    # ...and no unscoped accept smuggled in alongside it.
    rules = [ln for ln in res.stdout.splitlines() if not ln.startswith("#")]
    assert all("saddr" in ln for ln in rules), rules


def test_ssh_v6_allowlist_renders_ip6_saddr() -> None:
    res = _render_ssh('["2001:db8::/32"]')
    assert res.returncode == 0, res.stderr
    assert "ip6 saddr" in res.stdout
    assert "2001:db8::/32" in res.stdout
    assert "ip saddr" not in res.stdout.replace("ip6 saddr", "")


def test_ssh_mixed_families_render_one_rule_each() -> None:
    res = _render_ssh('["10.0.0.0/8","2001:db8::/32"]', port="2222")
    assert res.returncode == 0, res.stderr
    rules = [ln for ln in res.stdout.splitlines() if not ln.startswith("#")]
    assert len(rules) == 2, rules
    assert any("ip saddr" in ln and "10.0.0.0/8" in ln for ln in rules)
    assert any("ip6 saddr" in ln and "2001:db8::/32" in ln for ln in rules)
    assert all("tcp dport 2222" in ln for ln in rules)


def test_ssh_empty_list_still_opens_unconditionally() -> None:
    """An empty allowlist is a legitimate answer meaning "any source"."""
    res = _render_ssh("[]")
    assert res.returncode == 0, res.stderr
    rules = [ln for ln in res.stdout.splitlines() if not ln.startswith("#")]
    assert rules == ['tcp dport 22 accept comment "spatium-ssh"']


@pytest.mark.parametrize("blank", ["", "   ", "null"])
def test_ssh_absent_list_is_treated_as_empty_not_as_an_error(blank: str) -> None:
    res = _render_ssh(blank)
    assert res.returncode == 0, res.stderr
    assert 'tcp dport 22 accept comment "spatium-ssh"' in res.stdout


@pytest.mark.parametrize(
    "bad",
    [
        "not json at all",
        '["10.0.0.0/8"',          # truncated
        '{"cidrs": ["10.0.0.0/8"]}',  # right data, wrong shape
        "[1, 2, 3]",              # a list, but of nothing usable
    ],
)
def test_ssh_unparseable_allowlist_refuses_rather_than_opening(bad: str) -> None:
    """Fail closed.  A blob we cannot read must never collapse into "open".

    An unscoped rule is indistinguishable from a correctly-empty one at every
    later surface, so the refusal has to happen here or not at all.
    """
    res = _render_ssh(bad)
    assert res.returncode != 0, f"accepted {bad!r} and rendered:\n{res.stdout}"
    assert "accept" not in res.stdout
    assert res.stderr.strip(), "refused silently — the operator gets no reason"


def test_everything_that_can_refuse_runs_before_the_sshd_drop_in() -> None:
    """A refusal must not leave sshd on a port with no firewall rule.

    Two paths in the enabled branch abort: the renderer now refuses an
    unparseable allowlist rather than opening the port to everyone, and
    ``nft -c -f`` has always refused a malformed CIDR. Both call ``fail``,
    which exits before ``reload_sshd`` — so the RUNNING daemon keeps the old
    port and nothing looks wrong, while the installed drop-in has already
    moved it. The next sshd start or reboot is the lockout, by which time the
    log line that explains it is long gone.

    The fragment is the only thing that opens a non-22 port, so staging and
    validating it first is what makes an abort a no-op. Ordering is the whole
    property, and it is invisible to `bash -n` and to review.
    """
    src = SSH_RELOAD.read_text(encoding="utf-8")
    enabled = src[src.index("    enabled)") : src.index("    disabled)")]
    lines = enabled.splitlines()

    def at(needle: str) -> int:
        hits = [i for i, ln in enumerate(lines) if needle in ln]
        assert len(hits) == 1, f"{needle!r} appears {len(hits)}x in the enabled branch"
        return hits[0]

    render = at('python3 - "$PORT" "$CIDR_JSON"')
    dry_run = at('nft -c -f "$NFT_MAIN"')
    sshd_install = at('install -o root -g root -m 0644 "$SSHD_TMP" "$SSHD_DROPIN"')
    ak_install = at('install -o "$ADMIN_USER" -g "$ADMIN_USER" -m 0600 "$AK_TMP"')

    assert render < sshd_install, (
        "the CIDR render can refuse, and now runs after the sshd drop-in is "
        "installed — an abort leaves the configured port unreachable (#1001)"
    )
    assert dry_run < sshd_install, (
        "the nft dry-run can refuse, and now runs after the sshd drop-in is "
        "installed — same lockout shape (#1001)"
    )
    assert dry_run < ak_install, (
        "a refusal now happens after authorized_keys was replaced, so the "
        "runner aborts having half-applied the operator's key set (#1001)"
    )


def test_the_scoped_rule_is_no_longer_dead_code_on_port_22() -> None:
    """#1001 made the allowlist render correctly; #1009 made it reachable.

    Both were needed, and for a while only the first was done. The base
    ``/etc/nftables.conf`` opened ``tcp dport 22`` unconditionally ABOVE the
    ``include "/etc/nftables.d/*.nft"`` glob, and nftables is first-match-wins
    — verified against a real kernel, both rules loaded, the unconditional one
    listed first — so a perfectly-rendered scoped rule restricted nothing on
    the default port.

    That floor now lives in the retireable sentinel
    ``/etc/nftables.d/00-spatium-ssh.nft`` (#1009), which the firewall
    renderers retire under ``ssh_lockdown``. This test guards the half that
    lives in this file's subject matter: the base config must not take the
    accept back, because a rule there cannot be retired by anything.

    The rest of the mechanism — the sentinel, both host runners, and the
    second unconditional accept the renderers emit AFTER the scoped rule —
    is pinned by ``test_firewall_ssh_sentinel.py``.
    """
    base = (
        Path(__file__).parent.parent / "mkosi.extra" / "etc" / "nftables.conf"
    ).read_text(encoding="utf-8")
    for line in base.splitlines():
        code = line.split("#", 1)[0].strip()
        assert code != "tcp dport 22 accept", (
            "the unconditional port-22 accept is back in the base config, "
            "where nothing can retire it — the ssh source-CIDR allowlist is "
            "dead code again on the default port (#1001 / #1009)"
        )
    assert 'include "/etc/nftables.d/*.nft"' in base, (
        "the drop-in glob is gone, so neither the floor nor the scoped rule "
        "reaches the chain at all"
    )


# --------------------------------------------------------------------------
# 2. spatiumddi-syslog-reload — the CA PEMs must reach disk
# --------------------------------------------------------------------------
SYSLOG_MARKER = 'python3 - "$CA_DIR" "$CA_JSON"'


def test_syslog_ca_blob_is_written_to_disk(tmp_path: Path) -> None:
    ca_dir = tmp_path / "ca"
    ca_dir.mkdir()
    pem = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----"
    blob = json.dumps({str(ca_dir / "corp-root.pem"): pem})

    snippet = _extract_heredoc_command(SYSLOG_RELOAD, SYSLOG_MARKER)
    res = _run(snippet, {"CA_DIR": str(ca_dir), "CA_JSON": blob})

    assert res.returncode == 0, res.stderr
    written = ca_dir / "corp-root.pem"
    assert written.exists(), f"CA PEM never staged; stdout={res.stdout!r}"
    assert written.read_text(encoding="utf-8") == pem + "\n"
    assert "staged 1 CA file(s)" in res.stdout


def test_syslog_ca_blob_cannot_escape_the_managed_dir(tmp_path: Path) -> None:
    """The path guard still holds now that the blob actually arrives.

    Before #1001 this test could not fail: nothing was ever written, so a
    traversal would have "passed" for the wrong reason.
    """
    ca_dir = tmp_path / "ca"
    ca_dir.mkdir()
    escape = tmp_path / "escaped.pem"
    blob = json.dumps({str(escape): "-----BEGIN CERTIFICATE-----"})

    snippet = _extract_heredoc_command(SYSLOG_RELOAD, SYSLOG_MARKER)
    res = _run(snippet, {"CA_DIR": str(ca_dir), "CA_JSON": blob})

    assert res.returncode == 0, res.stderr
    assert not escape.exists(), "wrote outside the managed CA dir"


# --------------------------------------------------------------------------
# 3. spatiumddi-image-prune — the inventory must reach the selector
# --------------------------------------------------------------------------
PRUNE_MARKER = 'python3 - "$SLOT_VERSIONS" "$IMAGES_JSON" "$SLOT_IMAGE_TAGS" "$ACTIVE_IMAGE_TAG_FILE"'

_SP = "ghcr.io/spatiumnorth/"


def _run_prune(
    tmp_path: Path,
    images: dict,
    slots: dict,
    tags: dict | None = None,
    active_tag: str | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run the selector with a stubbed ``k3s`` so the in-use query resolves.

    ``tags`` is slot-image-tags.json and ``active_tag`` the running slot's
    baked spatiumddi-version (#1202); either left None is simply absent, as on
    an appliance whose sync-versions predates the sidecar.
    """
    images_json = tmp_path / "images.json"
    images_json.write_text(json.dumps(images), encoding="utf-8")
    slot_versions = tmp_path / "slot-versions.json"
    slot_versions.write_text(json.dumps(slots), encoding="utf-8")
    slot_tags = tmp_path / "slot-image-tags.json"
    if tags is not None:
        slot_tags.write_text(json.dumps(tags), encoding="utf-8")
    active_file = tmp_path / "spatiumddi-version"
    if active_tag is not None:
        active_file.write_text(active_tag + "\n", encoding="utf-8")

    # The selector shells out to `k3s crictl ps` for the in-use set; #555 makes
    # a failure there bail entirely, so the stub has to answer.
    stub_dir = tmp_path / "bin"
    stub_dir.mkdir()
    k3s = stub_dir / "k3s"
    k3s.write_text('#!/bin/bash\necho \'{"containers": []}\'\n', encoding="utf-8")
    k3s.chmod(0o755)

    snippet = _extract_heredoc_command(IMAGE_PRUNE, PRUNE_MARKER)
    return _run(
        snippet,
        {
            "SLOT_VERSIONS": str(slot_versions),
            "IMAGES_JSON": str(images_json),
            "SLOT_IMAGE_TAGS": str(slot_tags),
            "ACTIVE_IMAGE_TAG_FILE": str(active_file),
            "PATH": f"{stub_dir}:{os.environ.get('PATH', '/usr/bin:/bin')}",
        },
    )


def test_prune_sees_the_image_inventory(tmp_path: Path) -> None:
    """The inventory must reach the selector at all.

    Before #1001 this printed nothing for every input — the documented
    fail-safe ``except: sys.exit(0)`` turned the discarded pipe into
    "nothing to prune", so the disk-reclaim feature had never reclaimed
    anything and reported success doing it.
    """
    images = {
        "images": [
            {"id": "sha256:stale", "repoTags": [_SP + "api:2026.01.01-1"]},
            {"id": "sha256:keep_a", "repoTags": [_SP + "api:2026.09.01-1"]},
            {"id": "sha256:keep_b", "repoTags": [_SP + "api:2026.09.02-1"]},
        ]
    }
    res = _run_prune(tmp_path, images, {"slot_a": "2026.09.01-1", "slot_b": "2026.09.02-1"})
    assert res.returncode == 0, res.stderr
    assert res.stdout.split() == ["sha256:stale"], res.stdout


def test_prune_never_touches_non_spatiumddi_images(tmp_path: Path) -> None:
    images = {
        "images": [
            {"id": "sha256:coredns", "repoTags": ["rancher/mirrored-coredns:1.11"]},
            {"id": "sha256:pause", "repoTags": ["rancher/mirrored-pause:3.6"]},
        ]
    }
    res = _run_prune(tmp_path, images, {"slot_a": "2026.09.01-1", "slot_b": "2026.09.02-1"})
    assert res.returncode == 0, res.stderr
    assert res.stdout.strip() == ""


def test_prune_keeps_everything_when_slot_versions_are_unknown(tmp_path: Path) -> None:
    """The fail-safe still holds — it just no longer fires on every run."""
    images = {"images": [{"id": "sha256:stale", "repoTags": [_SP + "api:2026.01.01-1"]}]}
    res = _run_prune(tmp_path, images, {"slot_a": "unknown", "slot_b": ""})
    assert res.returncode == 0, res.stderr
    assert res.stdout.strip() == ""


# --------------------------------------------------------------------------
# 3b. #1202 — a nightly slot's images are kept by the tag they carry
# --------------------------------------------------------------------------
# The strings are the ones the 2026.09.04-1 -> nightly-2026.09.24 upgrade wrote:
# slot-versions.json records each slot's APPLIANCE_VERSION, and a nightly's is
# not its image tag (.github/workflows/nightly.yml passes the two apart).
_NIGHTLY_SLOTS = {"slot_a": "2026.09.04-1", "slot_b": "0.0.0-nightly-20260924+7490f61"}
_NIGHTLY_TAGS = {"slot_a": "2026.09.04-1", "slot_b": "nightly-20260924"}


def _upgraded_inventory() -> dict:
    return {
        "images": [
            {"id": "sha256:sup_new", "repoTags": [_SP + "spatium-supervisor:nightly-20260924"]},
            {"id": "sha256:kea_new", "repoTags": [_SP + "dhcp-kea:nightly-20260924"]},
            # Built from parts: a literal `…-api:<date tag>` reads as a key to
            # the pre-push secret scan.
            {"id": "sha256:api_new", "repoTags": [_SP + "spatiumddi-api:" + _NIGHTLY_TAGS["slot_b"]]},
            {"id": "sha256:sup_old", "repoTags": ["ghcr.io/spatiumddi/spatium-supervisor:2026.09.04-1"]},
            {"id": "sha256:api_old", "repoTags": ["ghcr.io/spatiumddi/spatiumddi-api:2026.09.04-1"]},
            {"id": "sha256:stale", "repoTags": ["ghcr.io/spatiumddi/spatiumddi-api:2026.08.12-1"]},
        ]
    }


def test_prune_keeps_the_committed_nightly_slots_images_by_their_tag(tmp_path: Path) -> None:
    """#1202: right after the trial commit nothing holds the new slot's images
    yet. Matched on the appliance version alone, every one of them was deleted
    ("removed 8/8"), and spatium-supervisor (pull policy Never) never came back.
    With each slot's image tag, only the genuinely stale release goes."""
    res = _run_prune(tmp_path, _upgraded_inventory(), _NIGHTLY_SLOTS, tags=_NIGHTLY_TAGS)
    assert res.returncode == 0, res.stderr
    assert res.stdout.split() == ["sha256:stale"], res.stdout


def test_the_running_slots_baked_tag_protects_it_without_the_sidecar(tmp_path: Path) -> None:
    """A slot-image-tags.json an older sync-versions never wrote must not
    re-open #1202 for the slot being committed: its own baked tag covers it."""
    res = _run_prune(tmp_path, _upgraded_inventory(), _NIGHTLY_SLOTS, active_tag="nightly-20260924")
    assert res.returncode == 0, res.stderr
    assert res.stdout.split() == ["sha256:stale"], res.stdout


def test_a_previous_nightly_slot_stays_bootable_too(tmp_path: Path) -> None:
    """Nightly to nightly: neither slot's appliance version is a tag, so the
    rollback slot's images need the sidecar as much as the committed slot's."""
    images = {
        "images": [
            {"id": "sha256:n24", "repoTags": [_SP + "spatium-supervisor:nightly-20260924"]},
            {"id": "sha256:n23", "repoTags": [_SP + "spatium-supervisor:nightly-20260923"]},
            {"id": "sha256:n20", "repoTags": [_SP + "spatium-supervisor:nightly-20260920"]},
        ]
    }
    res = _run_prune(
        tmp_path,
        images,
        {"slot_a": "0.0.0-nightly-20260923+c13d8eb", "slot_b": "0.0.0-nightly-20260924+7490f61"},
        tags={"slot_a": "nightly-20260923", "slot_b": "nightly-20260924"},
    )
    assert res.returncode == 0, res.stderr
    assert res.stdout.split() == ["sha256:n20"], res.stdout


def test_known_tags_never_license_a_prune_the_versions_refuse(tmp_path: Path) -> None:
    """The fail-safe is the versions' call: unknown slot versions prune
    nothing, whatever tags are known."""
    res = _run_prune(
        tmp_path,
        _upgraded_inventory(),
        {"slot_a": "unknown", "slot_b": ""},
        tags=_NIGHTLY_TAGS,
        active_tag="nightly-20260924",
    )
    assert res.returncode == 0, res.stderr
    assert res.stdout.strip() == ""


# --------------------------------------------------------------------------
# 4. structural sweep — the pattern must not come back
# --------------------------------------------------------------------------
# ``python3 -`` (the program on stdin) as opposed to ``python3 -c`` / ``-m``.
_PY_DASH = re.compile(r"python3\s+-(?=\s|$)")
_HEREDOC = re.compile(r"<<-?'?([A-Za-z_][A-Za-z0-9_]*)'?\s*$")


def _bin_scripts() -> list[Path]:
    return sorted(p for p in BIN.iterdir() if p.is_file() and not p.name.endswith(".pyc"))


def test_no_runner_pipes_into_a_python_program_read_from_stdin() -> None:
    """A pipe into ``python3 -`` can only ever be discarded.

    Whether the body reads ``sys.stdin`` or not, the pipe is a lie: the
    heredoc owns fd 0.  Flag the shape itself rather than the symptom, so a
    reintroduction is caught before someone has to work out which ``except``
    is hiding it this time.
    """
    offenders = []
    for script in _bin_scripts():
        for n, line in enumerate(script.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
            if "|" not in line or not _PY_DASH.search(line):
                continue
            if line.index("|") > _PY_DASH.search(line).start():
                continue  # a pipe AFTER python3 - is just its output
            if _HEREDOC.search(line):
                offenders.append(f"{script.name}:{n}: {line.strip()}")
    assert not offenders, (
        "pipe into `python3 -` with a heredoc — the heredoc wins and the "
        "piped data is discarded (#1001). Pass the data as argv, or via a "
        "temp file when it is unbounded:\n  " + "\n  ".join(offenders)
    )


def test_no_python_dash_heredoc_body_reads_stdin() -> None:
    """``python3 - <<EOF`` whose body reads stdin always reads EOF.

    The companion to the test above: it catches the same defect written
    without a visible pipe on the command line (data staged into fd 0
    earlier, or a pipe that a later refactor removed while leaving the
    ``json.load(sys.stdin)`` behind).
    """
    offenders = []
    for script in _bin_scripts():
        lines = script.read_text(encoding="utf-8", errors="replace").splitlines()
        for n, line in enumerate(lines):
            if not _PY_DASH.search(line):
                continue
            opener = _HEREDOC.search(line)
            if not opener:
                continue
            delim = opener.group(1)
            end = next(
                (i for i in range(n + 1, len(lines)) if lines[i].strip() == delim), None
            )
            if end is None:
                continue
            body = "\n".join(lines[n + 1 : end])
            if "sys.stdin" in body:
                offenders.append(f"{script.name}:{n + 1} (heredoc {delim})")
    assert not offenders, (
        "`python3 -` reads its PROGRAM from stdin, so a heredoc body that "
        "also reads sys.stdin can only ever see EOF (#1001):\n  "
        + "\n  ".join(offenders)
    )
