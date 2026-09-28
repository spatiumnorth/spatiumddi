"""The version-pin manifest guard (#975).

``scripts/lint_versions.py`` is what makes ``versions.json`` a source of truth
rather than a 28th copy of every version string. These tests exercise it
against synthetic manifests in ``tmp_path`` rather than against the real tree:
the real tree is asserted by the script itself, which runs unconditionally in
CI's Backend Lint job, and a test that re-read the real files would silently
become a no-op in the dev container (which copies only ``backend/`` into the
image) — the skip-shaped hole that has bitten this repo before.

The cases that earn their keep are the negative ones. A guard is only worth
having if it fails when it should, and this repo has now been bitten four
times by one that did not (#1028, #1029, #1030, and #882's rotation): the
recurring shape is a check that evaluates nothing and prints the same line it
prints on success.
"""

from __future__ import annotations

import importlib.util
import json
import pathlib
import types

import pytest

_REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
_SCRIPT = _REPO_ROOT / "scripts" / "lint_versions.py"

# The dev container copies only ``backend/`` into the image, so this skips
# there and runs for real in CI, which tests from a full checkout. Same
# convention as test_ci_backend_relevant.py. A deleted script is caught loudly
# by the workflow step that invokes it, not by a silent skip here.
pytestmark = pytest.mark.skipif(
    not _SCRIPT.exists(),
    reason="version-pin linter not present in this checkout",
)


def _load() -> types.ModuleType:
    spec = importlib.util.spec_from_file_location("lint_versions", _SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def lint() -> types.ModuleType:
    return _load()


def _write(tmp_path: pathlib.Path, manifest: dict, files: dict[str, str]) -> pathlib.Path:
    for rel, body in files.items():
        target = tmp_path / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(body)
    path = tmp_path / "versions.json"
    path.write_text(json.dumps(manifest))
    return path


def _run(lint: types.ModuleType, path: pathlib.Path) -> int:
    return lint.main(["--manifest", str(path)])


# ── the happy path, and that it says how much it checked ─────────────────────


def test_agreeing_pins_pass(
    lint: types.ModuleType, tmp_path: pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = _write(
        tmp_path,
        {
            "components": {
                "helm": {
                    "version": "v3.21.4",
                    "pinned_in": [
                        {"path": "Makefile", "match": "alpine/helm:{version_no_v}"},
                        {"path": "ci.yml", "match": "version: {version}"},
                    ],
                }
            }
        },
        {"Makefile": "HELM_IMAGE ?= alpine/helm:3.21.4\n", "ci.yml": "  version: v3.21.4\n"},
    )
    assert _run(lint, path) == 0
    out = capsys.readouterr().out
    # "0 assertions" must not be able to print the same line as "all passed",
    # so the count is part of the success message (#1030).
    assert "2 pin assertion(s)" in out


def test_version_no_v_is_substituted(lint: types.ModuleType, tmp_path: pathlib.Path) -> None:
    """A release tag carries a leading ``v``; the image tag it produces does not.

    Without this the manifest would need a second copy of the number for helm
    (``v3.21.4`` in four workflows, ``3.21.4`` in the Makefile) — and a second
    copy is the thing the file exists to remove.
    """
    path = _write(
        tmp_path,
        {
            "components": {
                "h": {
                    "version": "v3.21.4",
                    "pinned_in": [{"path": "f", "match": "x:{version_no_v}"}],
                }
            }
        },
        {"f": "x:3.21.4"},
    )
    assert _run(lint, path) == 0


# ── the drift the guard exists for ───────────────────────────────────────────


def test_a_stale_literal_fails(
    lint: types.ModuleType, tmp_path: pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = _write(
        tmp_path,
        {
            "components": {
                "nginx": {"version": "1.31.5-alpine", "pinned_in": [{"path": "values.yaml"}]}
            }
        },
        {"values.yaml": "    tag: 1.30.3-alpine\n"},
    )
    assert _run(lint, path) == 1
    err = capsys.readouterr().err
    assert "nginx" in err and "values.yaml" in err


def test_partial_bump_of_a_multi_copy_file_fails(
    lint: types.ModuleType, tmp_path: pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Two of three bumped is the failure an "at least one" rule cannot see.

    The Patroni overlay runs three etcd services and three Redis containers.
    Bumping two leaves a mixed-version cluster — and a substring check with no
    count passes it, because the version IS present. This is the reason
    ``count`` exists.
    """
    manifest = {
        "components": {
            "etcd": {
                "version": "v3.5.33",
                "pinned_in": [{"path": "ha.yaml", "match": "etcd:{version}", "count": 3}],
            }
        }
    }
    partly_bumped = "  a: etcd:v3.5.33\n  b: etcd:v3.5.33\n  c: etcd:v3.5.30\n"
    path = _write(tmp_path, manifest, {"ha.yaml": partly_bumped})
    assert _run(lint, path) == 1
    assert "2×, expected 3×" in capsys.readouterr().err

    # Negative control: the same assertion passes once the third moves.
    (tmp_path / "ha.yaml").write_text(partly_bumped.replace("v3.5.30", "v3.5.33"))
    assert _run(lint, path) == 0


def test_a_renamed_file_is_an_error_not_a_skip(
    lint: types.ModuleType, tmp_path: pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A pin whose file moved is drift, and must not report as a pass.

    This is the whole failure class in one case: skipping what cannot be
    found turns a rename into a clean run, and the pin is then unguarded with
    nothing anywhere saying so.
    """
    path = _write(
        tmp_path,
        {
            "components": {
                "k3s": {"version": "v1.36.4+k3s1", "pinned_in": [{"path": "gone/Makefile"}]}
            }
        },
        {},
    )
    assert _run(lint, path) == 1
    assert "does not exist" in capsys.readouterr().err


# ── the manifest itself must be unusable-loudly, never vacuously-fine ────────


@pytest.mark.parametrize(
    ("manifest_text", "why"),
    [
        ("{}", "no components key at all"),
        ('{"components": {}}', "an empty components map would assert nothing"),
        ("not json", "an unparseable manifest"),
        ('{"components": {"x": {"pinned_in": [{"path": "f"}]}}}', "a component with no version"),
        (
            '{"components": {"x": {"version": "1", "pinned_in": []}}}',
            "a component that asserts nothing",
        ),
        (
            '{"components": {"x": {"version": "1", "pinned_in": [{"path": "f", "count": 0}]}}}',
            "a count of zero would assert the pin is ABSENT",
        ),
    ],
)
def test_unusable_manifest_fails(
    lint: types.ModuleType, tmp_path: pathlib.Path, manifest_text: str, why: str
) -> None:
    path = tmp_path / "versions.json"
    path.write_text(manifest_text)
    (tmp_path / "f").write_text("1")
    assert _run(lint, path) == 1, f"should have failed: {why}"


def test_missing_manifest_fails(lint: types.ModuleType, tmp_path: pathlib.Path) -> None:
    assert _run(lint, tmp_path / "nope.json") == 1


# ── the upstream comparator ──────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("pinned", "upstream", "same", "why"),
    [
        ("v1.36.4+k3s1", "v1.36.4+k3s1", True, "identical"),
        ("v0.15.3", "metallb-chart-0.16.1", False, "chart tags carry a repo prefix"),
        ("0.29.0", "cloudnative-pg-v0.29.0", True, "prefixed tag, same version"),
        ("10.4.1", "frr-10.7.1", False, "prefixed tag, behind"),
        (
            "v0.0.21",
            "frr-k8s-chart-0.0.26",
            False,
            "the '8' in 'k8s' must not be read as the version",
        ),
        ("v0.0.21", "frr-k8s-chart-0.0.21", True, "same, with the same 'k8s' trap"),
        ("8.10.1-alpine", "8.10.1-alpine", True, "base-OS suffix on both sides"),
        ("16-alpine", "18-alpine", False, "no dotted run — fall back to digits"),
        ("3.4-slim", "3.4-slim", True, "slim suffix"),
        ("latest", "latest", True, "no digits at all"),
    ],
)
def test_comparable_handles_every_tag_shape(
    lint: types.ModuleType, pinned: str, upstream: str, same: bool, why: str
) -> None:
    assert (lint._comparable(pinned) == lint._comparable(upstream)) is same, why


def test_upstream_kind_none_reports_no_upstream(lint: types.ModuleType) -> None:
    """Entries lock-stepped to another component declare no upstream.

    ``kind-node`` follows k3s's Kubernetes minor and ``patroni-image`` is an
    image this repo does not publish. Both must render as "no upstream", never
    as a failed lookup — a report where a deliberate non-answer looks like an
    error is one people stop reading.
    """
    assert lint.resolve_upstream({"upstream": {"kind": "none"}}, None) is None
    assert lint.resolve_upstream({}, None) is None


def test_upstream_table_separates_holds_from_real_drift(lint: types.ModuleType) -> None:
    rows = [
        {"name": "a", "current": "1", "latest": "2", "behind": True, "hold": None, "error": None},
        {
            "name": "b",
            "current": "1",
            "latest": "2",
            "behind": True,
            "hold": "on purpose",
            "error": None,
        },
        {"name": "c", "current": "2", "latest": "2", "behind": False, "hold": None, "error": None},
        {
            "name": "d",
            "current": "1",
            "latest": None,
            "behind": False,
            "hold": None,
            "error": "boom",
        },
    ]
    table = lint.format_upstream_table(rows)
    lines = {row.split("|")[1].strip(): row for row in table.splitlines()}
    assert "⬆️ behind" in lines["`a`"]
    assert "held on purpose" in lines["`b`"]
    assert "current" in lines["`c`"]
    assert "check failed" in lines["`d`"]


# ── the review findings, each pinned so it cannot come back ─────────────────


def test_check_is_a_real_flag_and_runs_the_offline_mode(
    lint: types.ModuleType, tmp_path: pathlib.Path
) -> None:
    """``--check`` must be the offline assertion, not a prefix of something else.

    argparse resolves any unambiguous PREFIX of a long option, so with only
    ``--check-upstream`` defined, ``--check`` — the mode this script's own
    docstring documents — silently became the advisory NETWORK mode, which
    always exits 0. Following the documentation turned the guard off.
    """
    path = _write(
        tmp_path,
        {"components": {"x": {"version": "9.9.9", "pinned_in": [{"path": "f"}]}}},
        {"f": "nothing like it here"},
    )
    # Offline mode is the one that can FAIL; the upstream mode never does.
    assert lint.main(["--manifest", str(path), "--check"]) == 1


def test_undefined_options_are_rejected_rather_than_abbreviated(
    lint: types.ModuleType, tmp_path: pathlib.Path
) -> None:
    path = _write(
        tmp_path, {"components": {"x": {"version": "1", "pinned_in": [{"path": "f"}]}}}, {"f": "1"}
    )
    with pytest.raises(SystemExit):
        lint.main(["--manifest", str(path), "--check-up"])


@pytest.mark.parametrize(
    ("manifest", "why"),
    [
        (
            {"components": {"x": {"version": "1", "pinned_in": [{"path": "f", "counts": 3}]}}},
            "a typo'd site key silently downgrades an exact count to 'at least one'",
        ),
        (
            {"components": {"x": {"version": "1", "pinned_in": [{"path": "f"}], "notes": "x"}}},
            "a typo'd component key is silently ignored",
        ),
        (
            {"components": {"x": {"version": "1", "pinned_in": [{"path": "f"}]}}, "holdz": []},
            "a typo'd top-level key is silently ignored",
        ),
    ],
)
def test_unknown_keys_are_refused(
    lint: types.ModuleType, tmp_path: pathlib.Path, manifest: dict, why: str
) -> None:
    """A typo in the manifest is a guard that quietly stops guarding.

    ``"counts": 3`` leaves ``count`` unset, so an exact-occurrence assertion
    becomes "at least one" and a 2-of-3 partial bump passes — the same failure
    the manifest exists to prevent, one level up.
    """
    path = _write(tmp_path, manifest, {"f": "1"})
    assert _run(lint, path) == 1, f"should have been refused: {why}"


def test_digest_pin_is_asserted_offline(lint: types.ModuleType, tmp_path: pathlib.Path) -> None:
    """A tag+digest component asserts both halves in the file.

    The offline lint cannot tell whether a digest BELONGS to a tag — that is
    what ``--check-upstream`` resolves — but it must at least require the
    literal to be present, or the field is decoration.
    """
    manifest = {
        "components": {
            "t": {
                "version": "15.4.0",
                "digest": "sha256:abc",
                "pinned_in": [{"path": "Dockerfile", "match": "VERSION={version}"}],
            }
        }
    }
    path = _write(tmp_path, manifest, {"Dockerfile": "ARG VERSION=15.4.0\nARG DIGEST=sha256:abc\n"})
    assert _run(lint, path) == 0

    (tmp_path / "Dockerfile").write_text("ARG VERSION=15.4.0\nARG DIGEST=sha256:STALE\n")
    assert _run(lint, path) == 1


def test_upstream_summary_reports_failures_as_their_own_number(
    lint: types.ModuleType, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """ "Could not check" must never be readable as "nothing is behind".

    The prose summary opens with "0 behind upstream" when EVERY lookup failed,
    so a consumer scraping the first number reports the fleet current and
    closes the drift issue on the one run that knew nothing. The machine-
    readable RESULT line carries ``failed`` for exactly this reason, and the
    workflow keys its indeterminate verdict off it.
    """
    manifest = {
        "components": {
            "a": {
                "version": "1",
                "pinned_in": [{"path": "f"}],
                "upstream": {"kind": "github-release", "repo": "x/y"},
            },
            "b": {
                "version": "1",
                "pinned_in": [{"path": "f"}],
                "upstream": {"kind": "github-release", "repo": "x/z"},
            },
        }
    }

    def boom(*_a: object, **_k: object) -> str:
        raise OSError("network down")

    monkeypatch.setattr(lint, "_latest_github", boom)
    rows = lint.check_upstream(manifest, None)
    assert all(r["error"] for r in rows)
    assert not any(r["behind"] for r in rows), "a failed lookup must not read as 'behind'"

    # And the reported shape a consumer parses.
    behind = [r for r in rows if r["behind"] and not r["hold"]]
    failed = [r for r in rows if r["error"]]
    assert (len(behind), len(failed)) == (0, 2)


@pytest.mark.parametrize(
    ("url", "allowed", "why"),
    [
        ("https://api.github.com/repos/x/y/releases/latest", True, "the real endpoint"),
        ("https://hub.docker.com/v2/repositories/library/redis/tags", True, "docker hub"),
        ("https://quay.io/api/v1/repository/coreos/etcd/tag/", True, "quay"),
        ("https://rubygems.org/api/v1/versions/webrick/latest.json", True, "rubygems"),
        (
            "https://evil.example/api.github.com/repos/x/y",
            False,
            "the substring check this replaced would have sent the TOKEN here",
        ),
        ("https://api.github.com.evil.example/x", False, "suffix-attached lookalike host"),
        ("http://api.github.com/x", False, "plaintext downgrade"),
        ("file:///etc/passwd", False, "non-http scheme"),
    ],
)
def test_only_allowlisted_https_hosts_are_fetched(
    lint: types.ModuleType, url: str, allowed: bool, why: str
) -> None:
    """The token must be scoped by parsed HOSTNAME, never a URL substring.

    ``"api.github.com" in url`` is also true of
    ``https://evil.example/api.github.com/...`` — which is a credential
    handed to whoever owns that domain. Flagged by CodeQL as incomplete URL
    substring sanitization; the guard now parses the URL and matches the host
    exactly, and refuses anything that is not https to a known endpoint.
    """
    import urllib.parse

    parts = urllib.parse.urlsplit(url)
    host = (parts.hostname or "").lower()
    ok = parts.scheme == "https" and host in lint._ALLOWED_HOSTS
    assert ok is allowed, why
    if allowed:
        assert (host == lint._GITHUB_API_HOST) == ("api.github.com" == host)


# ── ordering, not inequality (#1240) ─────────────────────────────────────────


@pytest.mark.parametrize(
    ("current", "latest", "behind", "why"),
    [
        ("2.5.4", "v2.5.3", False, "pin AHEAD of the upstream query is not behind (redoc)"),
        ("9.20.26-r0", "9.20.29-r0", True, "an Alpine patch release"),
        ("9.20.29-r0", "9.20.29-r1", True, "an Alpine -rN rebuild, often a security fix"),
        ("9.20.29-r1", "9.20.29-r0", False, "a newer rebuild pinned than the index shows"),
        ("9.20.29-r0", "9.20.29-r0", False, "identical"),
        ("v1.36.4+k3s1", "v1.37.0+k3s1", True, "k3s minor"),
        ("v0.0.21", "frr-k8s-chart-0.0.26", True, "the 'k8s' trap still ignored"),
        ("16-alpine", "18-alpine", True, "no dotted run: digits"),
        ("latest", "latest", False, "no number at all falls back to 'differs'"),
    ],
)
def test_behind_means_upstream_is_newer(
    lint: types.ModuleType, current: str, latest: str, behind: bool, why: str
) -> None:
    """``behind`` used to be ``!=``: a pin ahead of upstream (redoc 2.5.4 vs a
    2.5.3 GitHub release) was reported "behind", which invites a downgrade."""
    assert lint.is_behind(latest, current) is behind, why


# ── the Alpine package index upstream (#1240) ────────────────────────────────

_APKINDEX = (
    "C:Q1abc=\nP:bind\nV:9.20.29-r0\nA:x86_64\nT:The ISC DNS server\n\n"
    "C:Q1def=\nP:bind-tools\nV:9.20.29-r0\nA:x86_64\n\n"
    "C:Q1ghi=\nP:kea\nV:3.0.3-r0\nA:x86_64\n"
)


def test_apkindex_records_parse_to_full_versions(lint: types.ModuleType) -> None:
    """The ``-rN`` suffix must survive: a floor written against ``-r0`` has to
    see a security rebuild that only bumps it to ``-r1``."""
    assert lint.parse_apkindex(_APKINDEX) == {
        "bind": "9.20.29-r0",
        "bind-tools": "9.20.29-r0",
        "kea": "3.0.3-r0",
    }


def _apkindex_blob(text: str) -> bytes:
    import gzip
    import io
    import tarfile

    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w") as tar:
        data = text.encode()
        info = tarfile.TarInfo("APKINDEX")
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
    return gzip.compress(raw.getvalue())


def test_alpine_upstream_reads_the_index_for_the_manifests_branch(
    lint: types.ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    fetched: list[str] = []

    def fake_bytes(url: str, token: str | None = None) -> bytes:
        fetched.append(url)
        return _apkindex_blob(_APKINDEX)

    monkeypatch.setattr(lint, "_http_bytes", fake_bytes)
    entry = {"upstream": {"kind": "alpine-package", "repo": "main/bind"}}
    assert lint.resolve_upstream(entry, None, "3.24") == "9.20.29-r0"
    assert fetched == ["https://dl-cdn.alpinelinux.org/alpine/v3.24/main/x86_64/APKINDEX.tar.gz"]


@pytest.mark.parametrize(
    ("repo", "branch", "why"),
    [
        ("main/bind", None, "no alpine branch in the manifest must be an error, not a guess"),
        ("main/nosuchpkg", "3.24", "a package absent from the index is an error"),
        ("bind", "3.24", "repo must be <repository>/<package>"),
    ],
)
def test_alpine_upstream_failures_are_errors_not_answers(
    lint: types.ModuleType, monkeypatch: pytest.MonkeyPatch, repo: str, branch: str | None, why: str
) -> None:
    monkeypatch.setattr(lint, "_http_bytes", lambda url, token=None: _apkindex_blob(_APKINDEX))
    with pytest.raises(LookupError):
        lint.resolve_upstream({"upstream": {"kind": "alpine-package", "repo": repo}}, None, branch)


def test_alpine_cdn_is_an_allowed_host(lint: types.ModuleType) -> None:
    assert "dl-cdn.alpinelinux.org" in lint._ALLOWED_HOSTS
    assert lint._GITHUB_API_HOST != "dl-cdn.alpinelinux.org", "the token must never go to the CDN"
