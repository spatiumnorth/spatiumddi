"""The bake's staleness guard must key on INPUTS, not on the clock (#1029).

``bake-images.sh`` refuses to bake a SpatiumDDI source image that is out
of date, so an operator who edits code and forgets ``make build`` does
not silently ship a stale ISO. It asked "is this image more than 24 h
old?", which cannot express that: a ``docker build`` that is a COMPLETE
CACHE HIT produces the identical image — same digest, same ID, same
``.Created`` — so an image whose inputs have not changed can never
refresh its own timestamp. It ages past 24 h and then blocks every bake
until somebody passes ``--allow-stale-images``, which is how a guard
stops being read at all.

Observed on the #999 ISO: ``make build`` rebuilt all eight images, and
exactly the three whose Dockerfiles a Dependabot bump had NOT touched
failed at 60 h. A ``docker build --pull`` reproducing the same image ID
proved every build input was unchanged.

So the question is now "was this image built AFTER its inputs last
moved?", answered from git. Three properties are pinned here:

* an image built after its last source change is FRESH however old it is
  — the filed bug;
* an image built before it is STALE however young it is — which the old
  wall-clock rule could not see at all, and which is the real "I forgot
  to rebuild" case;
* an UNCOMMITTED edit counts, because that is the commonest shape of
  that mistake and a commit-time-only comparison would miss it.

The tests execute the real shell functions extracted from the shipped
script — the bytes that ship, not a transcription — against a throwaway
git repository.

HOW TO RUN (from the repo root or this directory):
    python3 -m pytest appliance/tests/test_bake_input_staleness.py -v

No Docker, no root, no appliance ISO required.
"""

from __future__ import annotations

import os
import re
import subprocess
import time
from pathlib import Path

import pytest

from _installer_source import SCRIPTS, extract_fn  # noqa: E402 - sibling module

SCRIPT = SCRIPTS / "bake-images.sh"
SRC = SCRIPT.read_text()

_FUNCS = ("image_source_paths", "file_mtime", "image_inputs_mtime")


def _shipped_set_options() -> str:
    """The script's OWN ``set`` line, not a convenient subset.

    The first cut hardcoded ``set -uo pipefail`` — dropping the ``-e``
    the script actually runs under — and that is precisely why these
    tests passed over a bug that aborted the whole bake: a bare
    ``x="$(f)"`` assignment takes the substitution's exit status as its
    own, so under ``-e`` a non-zero return kills the script instead of
    reaching the caller's fallback. A harness that runs the shipped
    bytes in a shell the shipped bytes never see is not testing them.
    """
    m = re.search(r"^set -[a-z]+ ?[a-z]*$", SRC, re.M)
    assert m, "no 'set -...' line found in the shipped script"
    return m.group(0)


def _preamble() -> str:
    return (
        _shipped_set_options()
        + "\n"
        + "\n".join(extract_fn(f, SRC) for f in _FUNCS)
        + "\n"
    )


def _git(repo: Path, *args: str, **kw) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ)
    env.update(
        GIT_AUTHOR_NAME="t",
        GIT_AUTHOR_EMAIL="t@example.com",
        GIT_COMMITTER_NAME="t",
        GIT_COMMITTER_EMAIL="t@example.com",
    )
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True,
        text=True,
        check=True,
        env=env,
        **kw,
    )


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    """A git repo laid out like this one, with one commit."""
    r = tmp_path / "repo"
    for d in (
        "agent/supervisor",
        "agent/dns/spatium_dns_agent",
        "agent/dns/images/bind9",
        "agent/dns/images/powerdns",
        "agent/dns/images/technitium",
        "agent/dhcp",
        "agent/looking-glass",
        "backend",
        "frontend",
    ):
        (r / d).mkdir(parents=True, exist_ok=True)
        (r / d / "f.txt").write_text("v1\n")
    (r / "agent/dns/pyproject.toml").write_text("v1\n")
    subprocess.run(["git", "init", "-q", str(r)], check=True)
    _git(r, "add", "-A")
    _git(r, "commit", "-qm", "initial")
    return r


def _baked_images() -> list[str]:
    """The ``IMAGES=()`` entries, comments stripped.

    The array is heavily commented and several of those comments contain
    quoted prose, so a bare ``"([^"]+)"`` scrape picks up sentences —
    which is how the first cut of this test reported ``I built a Core but
    my image set was for Application`` as an unmapped image.
    """
    block = re.search(r"^IMAGES=\((.*?)^\)", SRC, re.M | re.S)
    assert block, "IMAGES=() array not found"
    code = "\n".join(
        line.split("#", 1)[0] for line in block.group(1).splitlines()
    )
    return re.findall(r'"([^"]+)"', code)


def _run(repo: Path, body: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["bash", "-c", f'REPO_ROOT="{repo}"\n' + _preamble() + body],
        capture_output=True,
        text=True,
        check=False,
    )


#: How a caller under ``set -e`` must invoke it — the bare form aborts.
#: This is the shape ``bake-images.sh`` itself now uses, so the tests
#: exercise the real call site rather than a laxer one.
_CALL = 'rc=0; out="$(image_inputs_mtime "{image}")" || rc=$?; echo "$out"; echo "rc=$rc"'


def _inputs_mtime(repo: Path, image: str) -> tuple[int, int]:
    r = _run(repo, _CALL.format(image=image))
    assert r.returncode == 0, r.stderr
    rc = int(re.search(r"rc=(\d+)", r.stdout).group(1))
    value = r.stdout.split("rc=")[0].strip()
    return (int(value) if value else 0), rc


# ── The mapping itself ─────────────────────────────────────────────


def test_every_baked_spatiumddi_image_has_a_source_path_mapping():
    """The guard-for-the-guard.

    An image added to ``IMAGES`` with no ``image_source_paths`` entry
    silently degrades to the weaker wall-clock rule. The script warns
    about that at runtime; this fails the build instead, because nobody
    reads a warning during a ten-minute ISO bake.
    """
    images = _baked_images()
    assert len(images) >= 8, images
    unmapped = []
    for image in images:
        r = subprocess.run(
            ["bash", "-c", _preamble() + f'image_source_paths "{image}"'],
            capture_output=True,
            text=True,
            check=False,
        )
        if r.returncode != 0 or not r.stdout.strip():
            unmapped.append(image)
    assert not unmapped, f"no image_source_paths() entry for: {unmapped}"


def test_mapped_paths_all_exist_in_this_repo():
    """A typo'd path makes ``git log`` answer for nothing, which reads as
    "inputs have never moved" — i.e. permanently fresh. Silent, and in
    the unsafe direction."""
    repo_root = SCRIPTS.parent.parent
    images = _baked_images()
    missing = []
    for image in images:
        r = subprocess.run(
            ["bash", "-c", _preamble() + f'image_source_paths "{image}"'],
            capture_output=True,
            text=True,
            check=False,
        )
        for path in r.stdout.split():
            if not (repo_root / path).exists():
                missing.append(f"{image} -> {path}")
    assert not missing, missing


def test_the_three_dns_images_do_not_share_one_coarse_mapping():
    """Deliberate, and load-bearing: a change under ``images/bind9/`` must
    not flag powerdns as stale, because rebuilding powerdns would be a
    cache hit that does not advance ``.Created`` — leaving the operator on
    a false alarm they cannot clear, which is #1029 itself."""
    got = {}
    for name in ("dns-bind9", "dns-powerdns", "dns-technitium"):
        r = subprocess.run(
            ["bash", "-c", _preamble() + f'image_source_paths "ghcr.io/spatiumnorth/{name}"'],
            capture_output=True,
            text=True,
            check=True,
        )
        got[name] = set(r.stdout.split())
    assert got["dns-bind9"] != got["dns-powerdns"]
    assert "agent/dns/images/bind9" in got["dns-bind9"]
    assert "agent/dns/images/bind9" not in got["dns-powerdns"]
    # The shared agent code must still be in all three.
    for paths in got.values():
        assert "agent/dns/spatium_dns_agent" in paths


# ── Input-drift detection ──────────────────────────────────────────


def test_a_commit_moves_the_input_timestamp(repo: Path):
    before, rc = _inputs_mtime(repo, "ghcr.io/spatiumnorth/spatiumddi-api")
    assert rc == 0
    time.sleep(1.1)
    (repo / "backend/f.txt").write_text("v2\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "touch backend")
    after, _ = _inputs_mtime(repo, "ghcr.io/spatiumnorth/spatiumddi-api")
    assert after > before


def test_an_uncommitted_edit_moves_the_input_timestamp(repo: Path):
    """The commonest shape of "I forgot to rebuild". A commit-time-only
    comparison would report the image as fresh."""
    before, _ = _inputs_mtime(repo, "ghcr.io/spatiumnorth/spatiumddi-api")
    time.sleep(1.1)
    (repo / "backend/f.txt").write_text("dirty\n")
    after, _ = _inputs_mtime(repo, "ghcr.io/spatiumnorth/spatiumddi-api")
    assert after > before


def test_an_untracked_file_moves_the_input_timestamp(repo: Path):
    before, _ = _inputs_mtime(repo, "ghcr.io/spatiumnorth/spatiumddi-api")
    time.sleep(1.1)
    (repo / "backend/brand_new.py").write_text("x\n")
    after, _ = _inputs_mtime(repo, "ghcr.io/spatiumnorth/spatiumddi-api")
    assert after > before


def test_an_edit_elsewhere_does_not_move_this_image(repo: Path):
    """The filed bug in one assertion: the api image must not be reported
    stale because the frontend changed."""
    before, _ = _inputs_mtime(repo, "ghcr.io/spatiumnorth/spatiumddi-api")
    time.sleep(1.1)
    (repo / "frontend/f.txt").write_text("v2\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "touch frontend")
    after, _ = _inputs_mtime(repo, "ghcr.io/spatiumnorth/spatiumddi-api")
    assert after == before


def test_a_notice_edit_moves_the_frontend_image(repo: Path):
    """#2895 — the frontend image copies the root NOTICE and LICENSE into the
    About page, so an edit to either is a frontend input like any file under
    ``frontend/``, and must not move the api image."""
    (repo / "NOTICE").write_text("v1\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "add NOTICE")
    fe_before, _ = _inputs_mtime(repo, "ghcr.io/spatiumnorth/spatiumddi-frontend")
    api_before, _ = _inputs_mtime(repo, "ghcr.io/spatiumnorth/spatiumddi-api")
    time.sleep(1.1)
    (repo / "NOTICE").write_text("v2\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "touch NOTICE")
    fe_after, _ = _inputs_mtime(repo, "ghcr.io/spatiumnorth/spatiumddi-frontend")
    api_after, _ = _inputs_mtime(repo, "ghcr.io/spatiumnorth/spatiumddi-api")
    assert fe_after > fe_before
    assert api_after == api_before


def test_a_bind9_only_change_does_not_move_powerdns(repo: Path):
    before, _ = _inputs_mtime(repo, "ghcr.io/spatiumnorth/dns-powerdns")
    time.sleep(1.1)
    (repo / "agent/dns/images/bind9/f.txt").write_text("v2\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "bind9 only")
    after, _ = _inputs_mtime(repo, "ghcr.io/spatiumnorth/dns-powerdns")
    bind_after, _ = _inputs_mtime(repo, "ghcr.io/spatiumnorth/dns-bind9")
    assert after == before
    assert bind_after > before


def test_shared_agent_code_moves_all_three_dns_images(repo: Path):
    before = {
        n: _inputs_mtime(repo, f"ghcr.io/spatiumnorth/{n}")[0]
        for n in ("dns-bind9", "dns-powerdns", "dns-technitium")
    }
    time.sleep(1.1)
    (repo / "agent/dns/spatium_dns_agent/f.txt").write_text("v2\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "shared agent")
    for name, was in before.items():
        now, _ = _inputs_mtime(repo, f"ghcr.io/spatiumnorth/{name}")
        assert now > was, name


# ── Fallbacks ──────────────────────────────────────────────────────


def test_an_unmapped_image_reports_rc_2_not_a_bogus_timestamp(repo: Path):
    """rc 2 is what makes the caller fall back to the wall-clock rule and
    NAME the image. Echoing 0 instead would read as "inputs have never
    moved" — permanently fresh, silently unguarded."""
    _, rc = _inputs_mtime(repo, "ghcr.io/spatiumnorth/some-new-image")
    assert rc == 2


def test_outside_a_git_repo_reports_rc_1(tmp_path: Path):
    """A tarball checkout has no git. Same reasoning: fall back loudly
    rather than answer 0."""
    plain = tmp_path / "notarepo"
    (plain / "backend").mkdir(parents=True)
    r = _run(plain, _CALL.format(image="ghcr.io/spatiumnorth/spatiumddi-api"))
    assert "rc=1" in r.stdout


def test_file_mtime_works_on_this_host(tmp_path: Path):
    """``stat -c`` is GNU, ``stat -f`` is BSD; the cross-build host is
    macOS. The same portability trap ``rfc3339_to_epoch`` was fixed for
    in #991 §4 — and one this function would fail SILENTLY on, since its
    caller skips a file whose mtime it cannot read."""
    f = tmp_path / "f"
    f.write_text("x")
    r = _run(tmp_path, f'file_mtime "{f}"')
    assert r.returncode == 0, r.stderr
    assert abs(int(r.stdout.strip()) - int(f.stat().st_mtime)) <= 1


# ── The guard must not abort the bake it guards ────────────────────


def _stub_build_host(bindir: Path) -> None:
    """Stub the two binaries the script requires of a build host.

    ``docker`` answers every call successfully, printing a fresh
    RFC 3339 timestamp. Unconditional on purpose: the existence probe
    redirects stdout to /dev/null, so one behaviour serves both calls.
    An earlier cut tried to tell them apart and got it wrong, which sent
    every image down the ``undated`` branch — and that branch
    ``continue``s BEFORE the assignment under test, so the test passed
    over the very bug it was written for.

    ``zstd`` is stubbed rather than skipped-around: the script's
    prerequisite check runs before the guard and aborts without it, so
    on a runner that has no zstd — the CI image, as it happens — a
    ``skipif`` would leave this test silently not running. Which is the
    failure class this whole change is about.
    """
    bindir.mkdir(parents=True, exist_ok=True)
    docker = bindir / "docker"
    docker.write_text(
        "#!/usr/bin/env bash\ndate -u +%Y-%m-%dT%H:%M:%S.000000000Z\nexit 0\n"
    )
    docker.chmod(0o755)
    zstd = bindir / "zstd"
    zstd.write_text("#!/usr/bin/env bash\nexit 0\n")
    zstd.chmod(0o755)


def _run_whole_script(tree: Path, tmp_path: Path) -> subprocess.CompletedProcess[str]:
    """The shipped script, end to end, in ``tree``."""
    bindir = tmp_path / "stubbin"
    _stub_build_host(bindir)
    env = dict(os.environ)
    env["PATH"] = f"{bindir}:{env['PATH']}"
    env["SPATIUMDDI_VERSION"] = "test"
    return subprocess.run(
        ["bash", str(tree / "appliance" / "scripts" / SCRIPT.name)],
        capture_output=True,
        text=True,
        check=False,
        env=env,
    )


@pytest.fixture
def tree(tmp_path: Path) -> Path:
    """A checkout-shaped directory with the shipped script in place and
    NO git repository — the tarball-download case."""
    t = tmp_path / "tree"
    (t / "appliance" / "scripts").mkdir(parents=True)
    for name in SCRIPT.parent.iterdir():
        if name.is_file():
            dest = t / "appliance" / "scripts" / name.name
            dest.write_bytes(name.read_bytes())
            dest.chmod(0o755)
    for d in ("backend", "frontend", "agent"):
        (t / d).mkdir()
    return t


def test_no_git_falls_back_instead_of_killing_the_bake(tree: Path, tmp_path: Path):
    """The regression that mattered most, and the one the first cut of
    THIS suite could not see.

    ``inputs="$(image_inputs_mtime ...)"`` is a bare assignment, and the
    script runs under ``set -e``: the substitution's non-zero status
    becomes the assignment's, so rc=1 (no git) and rc=2 (no mapping)
    killed the bake outright rather than reaching the ``case`` fallback
    below them — which was therefore dead code, while the CHANGELOG
    described it as the safety net. Outside a git repo the bake exited 1
    immediately after the version banner with nothing said about why.
    """
    r = _run_whole_script(tree, tmp_path)
    assert "no build-input mapping (or no git)" in r.stderr, r.stderr
    # It got PAST the guard: either into the bake proper or to a later
    # failure, but not aborted at the assignment.
    assert "fell back to the weaker" in r.stderr


def test_the_fallback_warning_is_not_dead_code(tree: Path, tmp_path: Path):
    """Same defect from the other side: every image must be NAMED, so a
    weaker check is never silent."""
    r = _run_whole_script(tree, tmp_path)
    for name in ("spatiumddi-api", "dns-bind9", "spatium-supervisor"):
        assert name in r.stderr, name


def test_an_uncommitted_deletion_moves_the_input_timestamp(repo: Path):
    """``git diff --name-only`` lists a deleted path, and the first cut
    skipped it with ``[ -f ] || continue`` — so removing a source file
    and not rebuilding left the image judged FRESH, which is exactly the
    "I forgot to rebuild" case the guard exists for. Resolved from the
    parent directory's mtime, which unlink() updates."""
    before, _ = _inputs_mtime(repo, "ghcr.io/spatiumnorth/spatiumddi-api")
    time.sleep(1.1)
    (repo / "backend/f.txt").unlink()
    after, _ = _inputs_mtime(repo, "ghcr.io/spatiumnorth/spatiumddi-api")
    assert after > before


def test_a_deletion_does_not_make_the_image_permanently_stale(repo: Path):
    """The reason a deletion resolves to the parent directory rather than
    to ``now``: a moving target would report the image stale on every
    run, including immediately after the rebuild that was supposed to
    clear it."""
    (repo / "backend/f.txt").unlink()
    first, _ = _inputs_mtime(repo, "ghcr.io/spatiumnorth/spatiumddi-api")
    time.sleep(1.1)
    second, _ = _inputs_mtime(repo, "ghcr.io/spatiumnorth/spatiumddi-api")
    assert first == second
