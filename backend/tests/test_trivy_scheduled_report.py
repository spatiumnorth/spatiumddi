"""The weekly Trivy scan must report CVEs, not just a count (#1095).

#1092 is the worked example: the tracking issue said the api image had 5
HIGH/CRITICAL fix-available vulnerabilities and contained **no CVE identifier
at all**. The scan captured ``head -c 12000`` of Trivy's *table* output, whose
Report Summary carries one row per scanned target — every
``site-packages/*.dist-info/METADATA`` file for that image. Measured: the full
table is 107,220 bytes and the first ``CVE-`` does not appear until byte
76,926, so the cap could only ever capture summary rows.

Two properties are pinned here, both of which have to hold for the issue to be
worth opening at all, and neither of which is visible in a green workflow run:

1. the report is rendered from ``--format json``, not from a byte-capped table;
2. ``rc=1`` is VALIDATED before being treated as findings. An unrecognised flag
   also exits 1 — verified against Trivy 0.74.0 — and writes ~15 KB of usage
   text to the captured stdout stream, so on an unpinned ``:latest`` image a
   CLI change would otherwise file a security issue whose body is Trivy's help.

This is a structural test: it asserts the shape of the shipped workflow rather
than running Trivy, which needs Docker and a vulnerability database.
"""

from __future__ import annotations

import pathlib
import re

import pytest

_REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
_WORKFLOW = _REPO_ROOT / ".github" / "workflows" / "trivy-scheduled.yml"

pytestmark = pytest.mark.skipif(
    not _WORKFLOW.exists(),
    reason="scheduled Trivy workflow not present in this checkout",
)


@pytest.fixture(scope="module")
def workflow() -> str:
    """The workflow with full-line comments stripped.

    Not tidiness: the block carries a comment explaining why it must NOT use
    ``--format table``, and matching raw text would fail on the rationale for
    the fix. Same trap ``scripts/lint_image_upgrades.py`` documents (#1088) —
    a file that explains a command is not a file that runs it.
    """
    return "\n".join(
        line for line in _WORKFLOW.read_text().splitlines() if not line.lstrip().startswith("#")
    )


def test_the_scan_emits_json(workflow: str) -> None:
    assert "--format json" in workflow, (
        "the scan must emit JSON — a byte-capped `--format table` puts Trivy's "
        "Report Summary ahead of the CVE detail and reports no CVE at all (#1095)"
    )
    assert "--format table" not in workflow, "a table capture would reintroduce #1095"


def test_the_report_is_not_a_byte_capped_dump(workflow: str) -> None:
    """``head -c`` of a Trivy report is the #1095 defect itself."""
    for match in re.finditer(r"head -c \d+ \"\$RUNNER_TEMP/trivy-", workflow):
        pytest.fail(f"byte-capped Trivy report capture reintroduced: {match.group(0)!r}")


def test_exit_code_one_is_validated_before_being_called_findings(workflow: str) -> None:
    """rc=1 means "findings" only if the output is actually a Trivy document."""
    assert "jq -e 'has(\"Results\")'" in workflow, (
        "rc=1 must be validated against the report: an unknown flag also exits 1 "
        "and writes usage text to stdout, which would be filed as CVEs (#1095)"
    )


def test_truncation_is_announced_and_cut_on_line_boundaries(workflow: str) -> None:
    """A silent cut is how #1095 stayed invisible; a byte cut also splits a row."""
    assert "head -n 200" in workflow, "the finding cap must be line-based, not byte-based"
    assert "Truncated: showing" in workflow, "truncation must state what it dropped"


def test_the_reproduction_hint_covers_the_image_that_has_findings(workflow: str) -> None:
    """`make trivy` takes agent images; `backend` is neither, and is the one
    that actually reports CVEs."""
    assert (
        "are not agent images" in workflow
    ), "the footer must not send a reader to `make trivy` for backend/frontend"


# ── #1392: MEDIUM/LOW findings with a fix, as an advisory ─────────────────────


def _advisory_block(workflow: str) -> str:
    start = workflow.index("--severity MEDIUM,LOW")
    end = workflow.index('echo "::endgroup::"', start)
    return workflow[start:end]


def test_the_advisory_pass_scans_medium_and_low_with_a_fix(workflow: str) -> None:
    """The pip CVEs that started #1392 were MEDIUM and LOW, and nothing we ran
    reported below HIGH, so they sat in the api image until a registry
    scanner at default severity showed them to a user."""
    assert "--severity MEDIUM,LOW --ignore-unfixed" in workflow


def test_the_advisory_never_feeds_the_gate(workflow: str) -> None:
    """An advisory finding must not set ``any``, the flag ``has_findings``
    comes from; it has its own ``adv`` and ``has_advisory``."""
    block = _advisory_block(workflow)
    assert "any=1" not in block, "an advisory finding must not mark the gate as failed"
    assert "adv=1" in block
    assert 'echo "has_advisory=$adv" >> "$GITHUB_OUTPUT"' in workflow


def test_the_gate_still_scans_only_high_and_critical(workflow: str) -> None:
    assert "--severity HIGH,CRITICAL --ignore-unfixed" in workflow


def test_the_tracking_issue_opens_on_either_and_closes_only_when_both_are_clean(
    workflow: str,
) -> None:
    assert "HAS_ADVISORY: ${{ steps.scan.outputs.has_advisory }}" in workflow
    assert "if (hasFindings || hasAdvisory) {" in workflow, (
        "an advisory alone must keep the tracking issue open, or MEDIUM/LOW "
        "findings would be reported nowhere but the run summary"
    )
    # Fail safe, as for has_findings: no definitive advisory result means the
    # issue is left alone, not closed.
    assert "[raw, rawAdv].every(v => v === '0' || v === '1')" in workflow
