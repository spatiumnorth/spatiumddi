"""The weekly README Contributors check (.github/scripts/check_contributors.py).

Runs the real script as a subprocess, so each test exercises the exit code
the workflow branches on. Exit 2 (could not evaluate) must never read as 0.
"""

from __future__ import annotations

import json
import pathlib
import subprocess
import sys

import pytest

_ROOT = pathlib.Path(__file__).resolve().parents[2]
_SCRIPT = _ROOT / ".github" / "scripts" / "check_contributors.py"

pytestmark = pytest.mark.skipif(
    not _SCRIPT.exists(), reason="needs a full checkout (.github/ above backend/)"
)

README = """# Project

Elsewhere: [@outsider](https://github.com/outsider) is only linked here.

## Contributors

| | Contributor | Area |
|---|---|---|
| <img src="https://github.com/alice.png"> | [@Alice](https://github.com/Alice) | x |
| | [@bob](https://github.com/bob) | y |

Opened a PR? See [issues](https://github.com/spatiumnorth/spatiumddi/issues).

---

## License

[@zed](https://github.com/zed)
"""


def _run(tmp_path, prs, readme=README, ignore=None):
    (tmp_path / "README.md").write_text(readme)
    (tmp_path / "prs.json").write_text(json.dumps(prs))
    ign = tmp_path / "ignore.txt"
    ign.write_text(ignore or "")
    return subprocess.run(
        [
            sys.executable,
            str(_SCRIPT),
            "--prs",
            str(tmp_path / "prs.json"),
            "--readme",
            str(tmp_path / "README.md"),
            "--ignore",
            str(ign),
        ],
        capture_output=True,
        text=True,
    )


def _pr(login, n=1):
    return {"login": login, "number": n}


def test_all_listed_exits_0(tmp_path):
    r = _run(tmp_path, [_pr("Alice"), _pr("bob", 2)])
    assert r.returncode == 0, r.stderr
    assert "OK: all 2 PR author(s)" in r.stdout


def test_one_missing_exits_1_and_names_it(tmp_path):
    r = _run(tmp_path, [_pr("Alice"), _pr("carol", 7), _pr("carol", 9)])
    assert r.returncode == 1
    assert "@carol" in r.stdout
    assert "#7" in r.stdout and "#9" in r.stdout
    assert "Alice" not in r.stdout


def test_case_insensitive_match(tmp_path):
    r = _run(tmp_path, [_pr("ALICE"), _pr("BoB", 2)])
    assert r.returncode == 0, r.stdout
    assert "OK: all 2 PR author(s)" in r.stdout


def test_bots_and_ignored_logins_skipped(tmp_path):
    prs = [
        _pr("Alice"),
        _pr("dependabot[bot]", 2),
        _pr("app/renovate", 3),
        _pr("Copilot", 4),
        _pr("copilot-swe-agent", 5),
        _pr("quiet-human", 6),
    ]
    r = _run(tmp_path, prs, ignore="# comment\nQuiet-Human  # trailing\n")
    assert r.returncode == 0, r.stdout
    assert "OK: all 6 PR author(s)" in r.stdout


def test_link_outside_section_does_not_count(tmp_path):
    # outsider (before the section) and zed (after it) are linked, not listed.
    r = _run(tmp_path, [_pr("outsider", 1), _pr("zed", 2)])
    assert r.returncode == 1
    assert "@outsider" in r.stdout and "@zed" in r.stdout


def test_no_contributors_section_exits_2(tmp_path):
    r = _run(tmp_path, [_pr("Alice")], readme="# Project\n\n## License\n")
    assert r.returncode == 2
    assert "Contributors" in r.stderr


def test_empty_pr_list_exits_2(tmp_path):
    r = _run(tmp_path, [])
    assert r.returncode == 2
    assert "empty" in r.stderr


def test_plain_login_strings_accepted(tmp_path):
    r = _run(tmp_path, ["Alice", "newperson"])
    assert r.returncode == 1 and "@newperson" in r.stdout
