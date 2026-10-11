"""The CI change-detection filter that decides whether THIS suite runs (#813, #821).

``.github/scripts/ci-backend-relevant.sh`` gates the 12 backend test shards. A
bug in it is uniquely bad: it doesn't fail loudly, it makes a PR go green
without having been tested. So the path list gets pinned here rather than
being validated by pushing branches and squinting at Actions.

The circularity is deliberate and safe in the direction that matters. The
script and its must-run manifest live under ``.github/scripts/``, which the
manifest itself declares as must-run — so any edit to the gate runs the suite
that contains this test.

Since #821 the deny-list covers ``agent/``, ``appliance/`` and ``.github/``
with carve-outs declared in ``ci-backend-must-run.txt``. Two tests here keep
that manifest honest: every entry must exist on disk, and every repo-root
escape in this test suite (a ``parents[2+]`` read) must be covered by an
entry — so a new cross-boundary read that nobody declared fails loudly
instead of silently losing coverage.
"""

from __future__ import annotations

import pathlib
import re
import subprocess

import pytest

_REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
_SCRIPT = _REPO_ROOT / ".github" / "scripts" / "ci-backend-relevant.sh"
_MANIFEST = _REPO_ROOT / ".github" / "scripts" / "ci-backend-must-run.txt"

# Every file in backend/tests that reaches OUTSIDE backend/ (via a
# ``parents[2]``-or-deeper path), mapped to what it reads. The scan test below
# fails when this map and reality disagree in either direction, and the
# coverage test pushes each read through the real gate script. Declaring a new
# entry here is only half the job — the read's prefix must also be in
# ci-backend-must-run.txt, or the gate would skip the suite on the very
# changes that break the test doing the reading.
# A value may be a tuple when one test reads several out-of-tree files —
# declaring only one of them would leave the other manifest prefix looking
# unnecessary, which is the drift this guard exists to prevent.
_KNOWN_REPO_ROOT_READS: dict[str, str | tuple[str, ...]] = {
    "test_spatium_console.py": "appliance/mkosi.extra/usr/local/bin/spatium-console",
    "test_appliance_join_auto_retry.py": (
        "appliance/mkosi.extra/usr/local/bin/spatium-cluster-join"
    ),
    "test_webui_selfcheck.py": ("appliance/mkosi.extra/usr/local/bin/spatiumddi-webui-selfcheck"),
    "test_appliance_firewall_render.py": (
        "agent/supervisor/spatium_supervisor/firewall_renderer.py"
    ),
    # #1468 — the group-name rule must match the supervisor's own pattern.
    "test_appliance_group_names.py": ("agent/supervisor/spatium_supervisor/role_orchestrator.py"),
    "test_ci_backend_relevant.py": ".github/scripts/ci-backend-relevant.sh",
    "test_openapi_export.py": "scripts/export_openapi.py",
    "test_merge_test_durations.py": "scripts/merge_test_durations.py",
    "test_test_impact_selection.py": ".github/scripts/select_impacted_tests.py",
    # #1353 — the outbound-host guard scans the four shipped agent packages
    # as well as backend/app, so an agent-only PR adding a host must run it.
    "test_outbound_hosts_documented.py": (
        "docs/PRIVACY.md",
        "agent/dhcp/spatium_dhcp_agent/",
        "agent/dns/spatium_dns_agent/",
        "agent/looking-glass/spatium_lg_agent/",
        "agent/supervisor/spatium_supervisor/",
        # ...and checks each scanned package is a carve-out in the manifest.
        ".github/scripts/ci-backend-must-run.txt",
    ),
    "test_zone_name_scope.py": "scripts/refresh_iana_tlds.py",
    "test_lint_versions.py": "scripts/lint_versions.py",
    "test_lint_workflow_shell.py": "scripts/lint_workflow_shell.py",
    "test_lint_image_upgrades.py": "scripts/lint_image_upgrades.py",
    "test_release_version_script.py": "scripts/release_version.py",
    "test_format_release_notes.py": "scripts/format_release_notes.py",
    "test_release_tags_script.py": ".github/scripts/release-tags.sh",
    "test_trivy_scan_script.py": ("scripts/trivy-scan.sh", "Makefile"),
    "test_trivy_scheduled_report.py": ".github/workflows/trivy-scheduled.yml",
    "test_trivy_pr_lanes.py": (
        ".github/workflows/build-dns-images.yml",
        ".github/workflows/build-dhcp-images.yml",
        ".github/workflows/build-looking-glass-images.yml",
        ".github/workflows/build-supervisor-image.yml",
    ),
    "test_dhcp_packet_loss.py": "agent/dhcp/spatium_dhcp_agent/metrics.py",
    # #1513 — the SVCB block is duplicated in the agent's Technitium driver.
    "test_technitium_svcb_parity.py": ("agent/dns/spatium_dns_agent/drivers/technitium.py"),
    "test_ntp_initial_seed.py": ("appliance/mkosi.extra/usr/local/bin/spatiumddi-firstboot"),
    # #972 — the HELD endpoint is mounted at the application root, so it needs
    # its own nginx location block in BOTH shipped templates or it falls
    # through to the SPA and a PBX asking where a phone is gets index.html.
    # The test reads both; both must therefore run this suite when edited.
    "test_e911_held.py": (
        "frontend/default.conf.template",
        "charts/spatiumddi/templates/frontend-tls-config.yaml",
    ),
}

# ``parents[2]`` from backend/tests/x.py is the repo root; anything at that
# depth or deeper escapes backend/. ``parents[1]`` (backend/) is in-tree and
# deliberately not matched.
_ESCAPE_RE = re.compile(r"parents\[[2-9]\]")

# The dev container copies only ``backend/`` into the image, so these skip
# there and run for real in CI, which tests from a full checkout. Same
# convention as test_spatium_console.py. A deleted script is caught loudly by
# the workflow step that invokes it, not by a silent skip here.
pytestmark = pytest.mark.skipif(
    not _SCRIPT.exists(),
    reason="CI change-detection script not present in this checkout",
)


def _relevant(*paths: str) -> bool:
    """Run the real script over a synthetic change set."""
    proc = subprocess.run(
        ["bash", str(_SCRIPT)],
        input="".join(f"{p}\n" for p in paths),
        capture_output=True,
        text=True,
        check=True,
    )
    out = proc.stdout.strip()
    assert out in ("true", "false"), f"unexpected output {out!r} (stderr: {proc.stderr})"
    return out == "true"


def _manifest_entries() -> list[str]:
    entries = []
    for raw in _MANIFEST.read_text().splitlines():
        line = raw.split("#", 1)[0].strip()
        if line:
            entries.append(line)
    return entries


def test_script_is_executable() -> None:
    """The workflow invokes it by path, so the +x bit has to be committed."""
    assert _SCRIPT.stat().st_mode & 0o111, f"{_SCRIPT} is not executable"


@pytest.mark.parametrize(
    "path",
    [
        "backend/app/main.py",
        "backend/tests/test_health.py",
        "backend/alembic/versions/abc123_thing.py",
        "backend/pyproject.toml",
    ],
)
def test_backend_paths_run_the_suite(path: str) -> None:
    assert _relevant(path)


@pytest.mark.parametrize(
    ("path", "why"),
    [
        (
            "appliance/mkosi.extra/usr/local/bin/spatium-console",
            "test_spatium_console.py loads this file directly — 52 tests",
        ),
        (
            "agent/supervisor/spatium_supervisor/firewall_renderer.py",
            "test_appliance_firewall_render.py imports this by path",
        ),
        (
            "agent/dns/spatium_dns_agent/drivers/powerdns.py",
            "test_outbound_hosts_documented.py scans the shipped agent packages (#1353)",
        ),
        (
            "agent/looking-glass/spatium_lg_agent/rib.py",
            "test_outbound_hosts_documented.py scans the shipped agent packages (#1353)",
        ),
        (
            ".github/scripts/ci-backend-relevant.sh",
            "the gate itself — an edit must run the suite that pins it",
        ),
        (
            ".github/scripts/ci-backend-must-run.txt",
            "the carve-out manifest — an edit must run the tests that enforce it",
        ),
        (
            ".github/workflows/ci.yml",
            "the workflow that orchestrates the shards",
        ),
    ],
)
def test_must_run_carveouts_run_the_suite(path: str, why: str) -> None:
    """Paths inside denied subtrees that the manifest carves back in.

    An allow-list of ``backend/**`` would have skipped every one of these,
    and the loss would have been invisible — a green PR with the tests never
    run.
    """
    assert _relevant(path), why


@pytest.mark.parametrize(
    "path",
    [
        "docs/features/DNS.md",
        "docs/index.md",
        "website/index.html",
        "frontend/src/App.tsx",
        "frontend/package.json",
        "charts/spatiumddi/values.yaml",
        "k8s/base/api.yaml",
        # #968 — perf/ has its own Perf — Tests job; before it was denied a
        # perf-only PR ran all 8 backend shards (PR #955, measured).
        "perf/generators/orchestrator/relay_sockets.py",
        "perf/generators/orchestrator/tests/test_relay_sockets.py",
        "perf/requirements.txt",
        "perf/README.md",
        "CHANGELOG.md",
        "README.md",
        "CLAUDE.md",
        "NOTICE",
        "LICENSE",
    ],
)
def test_known_irrelevant_paths_skip_the_suite(path: str) -> None:
    assert not _relevant(path)


@pytest.mark.parametrize(
    "path",
    [
        # The concrete change set that motivated #821: a nightly-workflow +
        # looking-glass-Dockerfile PR ran all 8 shards for nothing.
        ".github/workflows/nightly.yml",
        "agent/looking-glass/images/gobgp/Dockerfile",
        ".github/workflows/release.yml",
        ".github/workflows/docs-publish.yml",
        ".github/dependabot.yml",
        "agent/dhcp/images/kea/Dockerfile",
        # An agent's own tests are not shipped, so the outbound-host guard
        # (#1353) does not scan them and they stay denied.
        "agent/dns/tests/test_sync.py",
        "agent/looking-glass/tests/test_tls_verify.py",
        "agent/dns/README.md",
        "appliance/mkosi.conf",
        "appliance/mkosi.extra/etc/motd",
    ],
)
def test_denied_subtrees_skip_the_suite(path: str) -> None:
    """agent/, appliance/ and .github/ outside the carve-outs (#821).

    These have their own coverage — Agent — Tests, Appliance — Tests, and
    per-image build workflows — and nothing in the backend suite reads them
    (enforced by test_repo_root_escapes_match_the_declared_map below).
    """
    assert not _relevant(path)


def test_one_relevant_file_among_many_irrelevant_ones_runs_the_suite() -> None:
    """The decision is "any", not "most" — a single backend file counts."""
    assert _relevant(
        "docs/features/DNS.md",
        "CHANGELOG.md",
        "frontend/src/App.tsx",
        "backend/app/drivers/dns/bind9.py",
    )


def test_an_all_irrelevant_change_set_skips() -> None:
    assert not _relevant("docs/a.md", "docs/b.md", "frontend/src/x.ts", "CHANGELOG.md")


def test_an_empty_change_set_runs_the_suite() -> None:
    """Empty is not evidence of anything.

    It means the diff failed, or the caller piped nothing — both of which are
    upstream breakage, not "there is nothing to test".
    """
    assert _relevant()


@pytest.mark.parametrize(
    "path",
    [
        "terraform/main.tf",
        "ansible/playbook.yml",
        # (``perf/locustfile.py`` used to sit here as the example of an
        # unrecognised subtree — #968 made perf/ a recognised, denied one.)
        "loadtest/locustfile.py",
        "some-new-top-level-thing/x.py",
        "Makefile",
        "docker-compose.yml",
        "scripts/lint_migrations.py",
        ".env.example",
    ],
)
def test_unrecognised_paths_default_to_running(path: str) -> None:
    """The deny-list's whole point.

    Adding a directory nobody thought about must cost runner-minutes, never
    test coverage. If this test starts failing because someone widened the
    deny-list, the question to answer is "can the backend suite really not
    care about this?" — not "how do I make the test pass?".
    """
    assert _relevant(path)


def test_nested_markdown_is_not_blanket_skipped() -> None:
    """Only ROOT-level *.md is deny-listed.

    ``backend/app/README.md`` is unlikely to matter, but the pattern that
    would skip it would also skip a nested .md in a directory that does.
    """
    assert _relevant("backend/some/README.md")


def test_a_file_moved_out_of_backend_still_runs_the_suite() -> None:
    """Both sides of a rename have to reach the filter.

    ``git diff --name-only`` with rename detection ON — the default —
    reports only the DESTINATION, so ``git mv backend/thing.py
    docs/thing.md`` reads as a docs-only change while actually deleting a
    backend file. The workflow passes ``--no-renames`` to get both paths;
    this pins the filter's half of that contract.
    """
    assert _relevant("backend/thing.py", "docs/thing.md")


# ── Manifest enforcement (#821) ──────────────────────────────────────────────
# The deny-list only stays safe because the carve-out manifest cannot drift
# from what the suite actually reads. These three tests are that guarantee.


def test_manifest_entries_exist_on_disk() -> None:
    """No stale carve-outs.

    A prefix that matches nothing is not harmless: it documents a dependency
    that no longer exists, and the next person widening the deny-list will
    trust it.
    """
    entries = _manifest_entries()
    assert entries, f"{_MANIFEST} parsed to nothing"
    for entry in entries:
        target = _REPO_ROOT / entry.rstrip("/")
        assert target.exists(), f"manifest entry {entry!r} matches nothing on disk"


def test_repo_root_escapes_match_the_declared_map() -> None:
    """Every ``parents[2+]`` read in backend/tests is declared, and nothing else.

    This is what makes denying agent/ and appliance/ safe: a new test that
    reaches outside backend/ fails HERE with instructions, instead of the
    gate silently skipping the suite on the paths that test depends on. A
    comment or string that merely mentions ``parents[2]`` trips the scan too —
    that is the conservative direction; reword it or declare it.
    """
    found = {
        p.name
        for p in (_REPO_ROOT / "backend" / "tests").rglob("*.py")
        if _ESCAPE_RE.search(p.read_text())
    }
    declared = set(_KNOWN_REPO_ROOT_READS)
    assert found == declared, (
        f"repo-root escapes changed: undeclared={sorted(found - declared)} "
        f"stale={sorted(declared - found)}. Update _KNOWN_REPO_ROOT_READS and, "
        f"for new reads, add a covering prefix to {_MANIFEST.name}."
    )


def test_every_declared_read_is_covered_by_the_manifest() -> None:
    """The declared reads must actually run the suite through the real gate.

    Goes through the script rather than string-matching the manifest so the
    whole chain is exercised: read → manifest prefix → gate verdict.
    """
    for test_file, declared in _KNOWN_REPO_ROOT_READS.items():
        paths = (declared,) if isinstance(declared, str) else declared
        for read_path in paths:
            assert _relevant(read_path), (
                f"{test_file} reads {read_path}, but the gate would skip the "
                f"suite on that path — add a covering prefix to {_MANIFEST.name}"
            )
