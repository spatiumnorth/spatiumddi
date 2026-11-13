#!/usr/bin/env python3
"""Migration-shape linter for the expand/contract upgrade contract (issue #296).

SpatiumDDI runs rolling N→N+1 upgrades across multiple control-plane
nodes. During the 15–30 min mixed-version window, the database is
shared between still-old (N-1) and freshly-rebooted (N) application
pods. A destructive Alembic migration that drops a column N-1 still
reads will crash the old pods mid-upgrade.

The contract: every migration must be safe against BOTH N-1 and N
application code. The fix is expand/contract — release N adds the new
column / table / dual-write, release N+1 drops the old one once every
node is on N.

This script flags destructive ops so they get the two-release treatment
instead of one-shot.

Modes
-----
* Default (no args): scan all migrations, print non-baselined findings,
  exit 1 if any exist.
* --baseline: write the current set of findings to
  ``backend/alembic/migrations_lint_baseline.txt`` and exit 0. Run this
  once to capture historical violations.
* --show: print every finding regardless of baseline (debugging).

Stdlib only — no Alembic / SQLAlchemy import, so CI can run it without
the backend venv.
"""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from pathlib import Path

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------


def _find_repo_root() -> Path:
    """Locate the repo root by searching for ``backend/alembic/versions``.

    Normally the script lives at ``<repo>/scripts/lint_migrations.py``, so
    ``Path(__file__).parent.parent`` works. When invoked via stdin or with
    an alias, ``__file__`` may not be set; fall back to ``$SPATIUM_REPO_ROOT``
    then to the current working directory walking up.
    """
    import os

    env = os.environ.get("SPATIUM_REPO_ROOT")
    if env:
        candidate = Path(env).resolve()
        if (candidate / "backend" / "alembic" / "versions").is_dir():
            return candidate

    here = Path(globals().get("__file__", "")).resolve()
    if here.is_file():
        candidate = here.parent.parent
        if (candidate / "backend" / "alembic" / "versions").is_dir():
            return candidate

    cwd = Path.cwd().resolve()
    for parent in (cwd, *cwd.parents):
        if (parent / "backend" / "alembic" / "versions").is_dir():
            return parent

    # Fall back to the original guess so the error message is meaningful.
    return Path(__file__).resolve().parent.parent if "__file__" in globals() else cwd


REPO_ROOT = _find_repo_root()
MIGRATIONS_DIR = REPO_ROOT / "backend" / "alembic" / "versions"
BASELINE_PATH = REPO_ROOT / "backend" / "alembic" / "migrations_lint_baseline.txt"

# ---------------------------------------------------------------------------
# Patterns
# ---------------------------------------------------------------------------

# Each rule: (compiled regex, rule_id, human-readable reason).
#
# Use re.DOTALL so multi-line ``op.alter_column(...)`` calls match. Each
# pattern stops at the first ``)`` it can see only when the body is
# strictly one-line; for the alter_column cases we use a balanced-but-
# non-greedy ``[^)]*`` (good enough — Alembic calls don't usually nest
# parens in the kwargs, and any false positive here only over-flags,
# which the baseline handles).

PATTERNS = [
    (
        re.compile(r"\bop\.drop_column\s*\(", re.DOTALL),
        "drop_column",
        "dropping a column — old code still reads/writes during rolling upgrade; expand/contract instead",
    ),
    (
        re.compile(r"\bop\.drop_table\s*\(", re.DOTALL),
        "drop_table",
        "dropping a table — old code still queries it; archive-then-drop across two releases",
    ),
    (
        re.compile(
            r"\bop\.drop_constraint\s*\([^)]*type_\s*=\s*[\'\"]foreignkey[\'\"]",
            re.DOTALL,
        ),
        "drop_constraint_fk",
        "dropping a foreign key — can break inserts old code attempts",
    ),
    (
        re.compile(r"\bop\.alter_column\s*\([^)]*new_column_name\s*=", re.DOTALL),
        "rename_column",
        "renaming a column — use add-new + dual-write + backfill + drop-old across two releases",
    ),
    (
        re.compile(r"\bop\.rename_table\s*\(", re.DOTALL),
        "rename_table",
        "renaming a table — use add-new + dual-write + backfill + drop-old across two releases",
    ),
    (
        re.compile(r"\bop\.alter_column\s*\([^)]*\btype_\s*=", re.DOTALL),
        "alter_column_type",
        "changing a column type — type narrowing can corrupt data and break old code reads",
    ),
    # alter_column_not_null handled separately because it requires a
    # second pass to suppress add_column+notnull-in-same-migration.
]

# Separate regex for the alter_column nullable=False case — we extract
# the column name to decide whether to suppress.
ALTER_NOT_NULL_RE = re.compile(
    r"\bop\.alter_column\s*\(\s*"
    r"['\"](?P<table>[^'\"]+)['\"]\s*,\s*"
    r"['\"](?P<column>[^'\"]+)['\"][^)]*?"
    r"nullable\s*=\s*False",
    re.DOTALL,
)

# add_column(table, sa.Column("name", ...)) — capture the column name.
ADD_COLUMN_RE = re.compile(
    r"\bop\.add_column\s*\(\s*"
    r"['\"](?P<table>[^'\"]+)['\"]\s*,\s*"
    r"sa\.Column\s*\(\s*['\"](?P<column>[^'\"]+)['\"]",
    re.DOTALL,
)

# Safe-DDL rule (#1253). On a table that grows without bound a plain
# ``CREATE INDEX`` blocks every write for the whole build, and an ``ADD
# CONSTRAINT`` without ``NOT VALID`` scans the table under a lock that blocks
# writes; both queue every later query behind them. Use
# ``postgresql_concurrently=True`` inside ``op.get_context().autocommit_block()``
# for the index, and ``postgresql_not_valid=True`` + a later
# ``VALIDATE CONSTRAINT`` for the constraint. Tables created in the same file
# are empty and exempt.
LARGE_TABLES = frozenset(
    {
        "audit_log",
        "ip_address",
        "ip_mac_history",
        "subnet_utilization_history",
        "network_fdb_entry",
        "alert_event",
        "dns_record",
        "dns_query_log_entry",
        "dns_rpz_hit",
        "dns_metric_sample",
        "dhcp_metric_sample",
        "dhcp_lease",
        "dhcp_lease_history",
        "dhcp_log_entry",
    }
)

UNSAFE_DDL_RE = re.compile(
    r"\bop\.(?P<fn>create_index|create_foreign_key|create_check_constraint)\s*\("
    r"(?P<args>[^)]*(?:\([^)]*\)[^)]*)*)\)",
    re.DOTALL,
)
STR_ARG_RE = re.compile(r"['\"]([^'\"]+)['\"]")
CREATE_TABLE_RE = re.compile(r"\bop\.create_table\s*\(\s*['\"](?P<table>[^'\"]+)['\"]")


def _scan_unsafe_ddl(content: str, path: Path) -> list[Finding]:
    created = {m.group("table") for m in CREATE_TABLE_RE.finditer(content)}
    findings: list[Finding] = []
    for m in UNSAFE_DDL_RE.finditer(content):
        args = m.group("args")
        # create_index(name, table, ...), create_foreign_key(name, source, ...),
        # create_check_constraint(name, table, ...): the table is the 2nd string.
        strings = STR_ARG_RE.findall(args)
        kw = re.search(r"(?:table_name|source_table)\s*=\s*['\"]([^'\"]+)['\"]", args)
        table = kw.group(1) if kw else (strings[1] if len(strings) > 1 else "")
        if table not in LARGE_TABLES or table in created:
            continue
        if m.group("fn") == "create_index":
            if re.search(r"postgresql_concurrently\s*=\s*True", args):
                continue
            rule = "create_index_blocking"
        else:
            if re.search(r"postgresql_not_valid\s*=\s*True", args):
                continue
            rule = "add_constraint_validating"
        findings.append(
            Finding(
                path=str(path.relative_to(REPO_ROOT)),
                rule=rule,
                line=_line_of(content, m.start()),
                detail=_snippet(content, m.start()),
            )
        )
    return findings


# ---------------------------------------------------------------------------
# Data shapes
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Finding:
    """One flagged Alembic op."""

    path: str  # repo-relative
    rule: str
    line: int
    detail: str  # short context (the matched op signature snippet)


@dataclass(frozen=True)
class BaselineEntry:
    path: str
    rule: str
    line: int


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------


def _line_of(content: str, offset: int) -> int:
    """Convert a byte offset into a 1-based line number."""
    return content.count("\n", 0, offset) + 1


def _snippet(content: str, start: int, max_len: int = 100) -> str:
    """Return a single-line context snippet for the match start.

    The matched op may span multiple lines (alter_column with kwargs).
    Compact it to one line by collapsing whitespace and trimming.
    """
    # Walk back to the start of the line for cleaner context.
    line_start = content.rfind("\n", 0, start) + 1
    # Take ~max_len chars, collapse whitespace.
    raw = content[line_start : line_start + max_len + 40]
    # Stop at the first ``)`` — gives us the op signature header.
    if ")" in raw:
        raw = raw[: raw.index(")") + 1]
    flat = re.sub(r"\s+", " ", raw).strip()
    if len(flat) > max_len:
        flat = flat[: max_len - 1] + "…"
    return flat


def _scan_alter_not_null(content: str, path: Path) -> list[Finding]:
    """Find alter_column(nullable=False) calls NOT paired with a same-file add_column.

    The add_column+notnull-in-the-same-transaction case is atomic — the
    column starts non-NULL because every backfilled row got its value
    in the same DDL block. We only flag the standalone case where the
    operator is tightening an existing column that may contain NULL.
    """
    # Capture every add_column'd column in the file (any table — the
    # column name alone is a sufficient suppress signal in practice;
    # collisions across tables in one migration are vanishingly rare,
    # and a false suppress is still safer than a false flag here).
    added_columns: set[str] = set()
    for m in ADD_COLUMN_RE.finditer(content):
        added_columns.add(m.group("column"))

    findings: list[Finding] = []
    for m in ALTER_NOT_NULL_RE.finditer(content):
        col = m.group("column")
        if col in added_columns:
            continue  # atomic add+notnull is fine
        line = _line_of(content, m.start())
        findings.append(
            Finding(
                path=str(path.relative_to(REPO_ROOT)),
                rule="alter_column_not_null",
                line=line,
                detail=_snippet(content, m.start()),
            )
        )
    return findings


def scan_file(path: Path) -> list[Finding]:
    """Scan one migration file and return all findings (un-baselined)."""
    try:
        content = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return []

    findings: list[Finding] = []
    rel_path = str(path.relative_to(REPO_ROOT))

    for pattern, rule, _reason in PATTERNS:
        for m in pattern.finditer(content):
            line = _line_of(content, m.start())
            findings.append(
                Finding(
                    path=rel_path,
                    rule=rule,
                    line=line,
                    detail=_snippet(content, m.start()),
                )
            )

    findings.extend(_scan_alter_not_null(content, path))
    findings.extend(_scan_unsafe_ddl(content, path))

    # Deterministic ordering for stable baseline diffs.
    findings.sort(key=lambda f: (f.path, f.line, f.rule))
    return findings


def scan_all() -> list[Finding]:
    """Scan every ``backend/alembic/versions/*.py`` file."""
    out: list[Finding] = []
    for path in sorted(MIGRATIONS_DIR.glob("*.py")):
        if path.name == "__init__.py":
            continue
        out.extend(scan_file(path))
    return out


# ---------------------------------------------------------------------------
# Baseline
# ---------------------------------------------------------------------------

BASELINE_FUZZ = 5  # ±lines


def load_baseline() -> list[BaselineEntry]:
    if not BASELINE_PATH.exists():
        return []
    entries: list[BaselineEntry] = []
    for raw_line in BASELINE_PATH.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        # Format: path:rule:line
        parts = line.rsplit(":", 2)
        if len(parts) != 3:
            continue
        path, rule, lineno_s = parts
        try:
            lineno = int(lineno_s)
        except ValueError:
            continue
        entries.append(BaselineEntry(path=path, rule=rule, line=lineno))
    return entries


def write_baseline(findings: list[Finding]) -> None:
    """Write current findings to the baseline file, sorted."""
    lines = sorted({f"{f.path}:{f.rule}:{f.line}" for f in findings})
    header = (
        "# Auto-generated by scripts/lint_migrations.py --baseline.\n"
        "# Each line: <path>:<rule>:<line>. Matched with ±%d line fuzz so\n"
        "# trivial comment edits don't break the baseline. Re-run\n"
        "# `python3 scripts/lint_migrations.py --baseline` after intentional\n"
        "# changes to historical migrations.\n"
        "#\n" % BASELINE_FUZZ
    )
    BASELINE_PATH.write_text(header + "\n".join(lines) + "\n", encoding="utf-8")


def matches_baseline(finding: Finding, baseline: list[BaselineEntry]) -> bool:
    """True if ``finding`` corresponds to a baseline entry (within ±fuzz)."""
    for entry in baseline:
        if entry.path == finding.path and entry.rule == finding.rule:
            if abs(entry.line - finding.line) <= BASELINE_FUZZ:
                return True
    return False


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------


def reason_for(rule: str) -> str:
    if rule == "alter_column_not_null":
        return (
            "tightening NOT NULL on an existing column — backfill every NULL row first; "
            "one-shot will crash on any remaining NULL"
        )
    if rule == "create_index_blocking":
        return (
            "CREATE INDEX on a large table blocks writes for the whole build — use "
            "postgresql_concurrently=True inside op.get_context().autocommit_block()"
        )
    if rule == "add_constraint_validating":
        return (
            "adding a constraint to a large table scans it under a write-blocking lock — "
            "use postgresql_not_valid=True, then VALIDATE CONSTRAINT in a later step"
        )
    for _re, r, reason in PATTERNS:
        if r == rule:
            return reason
    return "destructive op"


def format_finding(f: Finding) -> str:
    return f"{f.path}:{f.line} :: {f.rule} :: {reason_for(f.rule)} (issue #296)"


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Lint Alembic migrations for ops that break the expand/contract "
            "rolling-upgrade contract (issue #296)."
        ),
    )
    parser.add_argument(
        "--baseline",
        action="store_true",
        help=(
            "Write all current findings to %s and exit 0. Use once to "
            "capture historical violations." % BASELINE_PATH.relative_to(REPO_ROOT)
        ),
    )
    parser.add_argument(
        "--show",
        action="store_true",
        help="Print every finding regardless of baseline (debug).",
    )
    args = parser.parse_args(argv)

    if not MIGRATIONS_DIR.exists():
        print(
            f"error: migrations directory not found at {MIGRATIONS_DIR}",
            file=sys.stderr,
        )
        return 2

    findings = scan_all()
    scanned = sum(
        1 for p in MIGRATIONS_DIR.glob("*.py") if p.name != "__init__.py"
    )

    if args.baseline:
        write_baseline(findings)
        print(
            f"Wrote {len(findings)} findings across {scanned} migrations "
            f"to {BASELINE_PATH.relative_to(REPO_ROOT)}"
        )
        return 0

    if args.show:
        for f in findings:
            print(format_finding(f))
        print(f"\n{len(findings)} total findings across {scanned} migrations.")
        return 0

    # Default mode: report non-baselined findings, fail on any.
    baseline = load_baseline()
    new_findings = [f for f in findings if not matches_baseline(f, baseline)]

    if not new_findings:
        baselined = len(findings) - len(new_findings)
        print(
            f"OK: no new destructive migration ops "
            f"({scanned} migrations scanned, {baselined} baselined)."
        )
        return 0

    print(
        f"FAIL: {len(new_findings)} new destructive migration op(s) detected. "
        f"Expand/contract is required for rolling upgrades — see issue #296.\n"
    )
    for f in new_findings:
        print(format_finding(f))
    print(
        "\nIf the destructive op is genuinely safe (e.g. dropping a "
        "column that was added in the same release and never reached "
        "production), update the baseline:\n"
        "  python3 scripts/lint_migrations.py --baseline\n"
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
