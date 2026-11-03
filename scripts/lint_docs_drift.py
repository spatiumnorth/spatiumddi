#!/usr/bin/env python3
"""Weekly drift check: do the docs diagrams and pages still match the code (#3414).

``make docs-verify`` checks diagram *geometry* (overflow, clipping). Nothing
checked whether a diagram is still *true*, and #3413 found most of the 29
diagrams had drifted -- Redis 7 labelled on a Redis 8 stack, a BIND 9.18 label
on 9.20, no Looking Glass collector, a field name that no model has. This is
the deterministic half of the answer: no network, no LLM, no database,
stdlib-only. Drift in *meaning* ("slave", a mocked-up page) stays a human job.

Four checks, one finding per line as ``file: kind: message``:

``version``
    A component version in a docs SVG ``<text>`` or a docs / README page must
    agree with ``versions.json`` (major, or major.minor when the label gives
    one). Matching is conservative: only the component names in the manifest's
    ``version_labels``, immediately followed by a version. ``BIND 9.18+`` (a
    minimum) is not a claim about what ships, so a trailing ``+`` is skipped.

``inventory``
    Every shipped workload -- compose service, chart Deployment / StatefulSet /
    DaemonSet, agent package, DNS / DHCP driver module, integration module --
    must be named in ``docs/assets/architecture.svg``, or sit in the manifest's
    ``inventory_allowlist`` with a reason.

``identifier``
    Code-style identifiers a mapped diagram shows (snake_case, CamelCase, or
    anything in a monospace ``<text>``) must exist in the model modules the
    manifest maps that diagram to: a class, ``__tablename__``, column or
    constraint name. A name matching the tail of a class (``RecordOp`` for
    ``DNSRecordOp``) is accepted -- diagrams shorten.

``path``
    A repo file path named in a diagram must exist.

The manifest is ``scripts/docs_drift_manifest.json``. Its allowlist is for
things that legitimately do not belong in the diagram, each with a reason;
it is not a place to park a diagram that is stale.

Exit codes: 0 clean, 1 findings, 2 the check itself could not run (missing
manifest, a source it reads has moved). A guard that evaluates nothing looks
exactly like one that passed (#1028-#1030), so every scan refuses an empty
inventory rather than reporting success on it.
"""

from __future__ import annotations

import argparse
import ast
import json
import pathlib
import re
import sys
from collections.abc import Iterable
from html import unescape

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
MANIFEST_NAME = "scripts/docs_drift_manifest.json"
MARKER = "<!-- docs-drift -->"

_MANIFEST_KEYS = {
    "$comment",
    "architecture_diagram",
    "version_labels",
    "version_exclude",
    "needles",
    "inventory_allowlist",
    "inventory_groups",
    "identifier_diagrams",
    "identifier_ignore",
    "path_roots",
}
_SKIP_DIRS = {".git", "node_modules", ".venv", "_site", "__pycache__", ".charts-render"}


class CheckError(Exception):
    """The check could not evaluate -- distinct from a finding."""


class Finding:
    def __init__(self, file: str, kind: str, message: str) -> None:
        self.file, self.kind, self.message = file, kind, message

    def line(self) -> str:
        return f"{self.file}: {self.kind}: {self.message}"


# --------------------------------------------------------------------- inputs


def load_manifest(root: pathlib.Path) -> dict:
    path = root / MANIFEST_NAME
    try:
        data = json.loads(path.read_text())
    except FileNotFoundError as exc:
        raise CheckError(f"{MANIFEST_NAME} is missing") from exc
    except json.JSONDecodeError as exc:
        raise CheckError(f"{MANIFEST_NAME} is not valid JSON: {exc}") from exc
    unknown = set(data) - _MANIFEST_KEYS
    if unknown:
        # A typo'd key is a section that silently stops guarding.
        raise CheckError(f"{MANIFEST_NAME}: unknown keys {sorted(unknown)}")
    for key in ("architecture_diagram", "version_labels", "path_roots"):
        if not data.get(key):
            raise CheckError(f"{MANIFEST_NAME}: {key!r} is missing or empty")
    for section in ("inventory_allowlist", "identifier_ignore"):
        for key, reason in data.get(section, {}).items():
            if not str(reason).strip():
                raise CheckError(
                    f"{MANIFEST_NAME}: {section} entry {key!r} has no reason"
                )
    return data


def _read(path: pathlib.Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        raise CheckError(f"cannot read {path}: {exc}") from exc


def svg_texts(svg: str) -> list[tuple[int, str, bool]]:
    """(line, text, monospace) for each ``<text>`` element."""
    out = []
    for m in re.finditer(r"<text\b([^>]*)>(.*?)</text>", svg, re.S):
        body = unescape(re.sub(r"<[^>]+>", "", m.group(2))).strip()
        if body:
            line = svg.count("\n", 0, m.start()) + 1
            out.append(
                (
                    line,
                    body,
                    "mono" in m.group(1).lower() or "mono" in m.group(2).lower(),
                )
            )
    return out


def diagram_files(root: pathlib.Path) -> list[pathlib.Path]:
    return sorted(p for p in (root / "docs").rglob("*.svg") if not _skipped(p, root))


def doc_pages(root: pathlib.Path, exclude: Iterable[str]) -> list[pathlib.Path]:
    skip = set(exclude)
    pages = [p for p in (root / "docs").rglob("*.md") if not _skipped(p, root)]
    if (root / "README.md").exists():
        pages.append(root / "README.md")
    return sorted(p for p in pages if p.relative_to(root).as_posix() not in skip)


def _skipped(p: pathlib.Path, root: pathlib.Path) -> bool:
    return bool(set(p.relative_to(root).parts) & _SKIP_DIRS)


def _rel(p: pathlib.Path, root: pathlib.Path) -> str:
    return p.relative_to(root).as_posix()


# -------------------------------------------------------------------- version


def _numeric(version: str) -> list[int]:
    m = re.search(r"\d+(?:\.\d+)*", version)
    return [int(x) for x in m.group(0).split(".")] if m else []


# "since Technitium 15.0", "between X 2.4 and 2.6": a claim about the past or a minimum,
# not about what ships now.
_HISTORICAL = re.compile(
    r"(?:since|before|until|prior to|older than|as on|between|from|and|to|[<>≤≥])[\s*_`]*$",
    re.I,
)


def check_versions(root: pathlib.Path, manifest: dict) -> list[Finding]:
    try:
        pins = json.loads((root / "versions.json").read_text())["components"]
    except (OSError, KeyError, json.JSONDecodeError) as exc:
        raise CheckError(f"versions.json unreadable: {exc}") from exc
    rules = []
    for key, pattern in manifest["version_labels"].items():
        if key not in pins:
            raise CheckError(f"version_labels names {key!r}, not in versions.json")
        shipped = _numeric(str(pins[key]["version"]))
        if not shipped:
            raise CheckError(f"versions.json {key!r} has no numeric version")
        # Group 1 is the label's version; a trailing '+' means "at least".
        rules.append(
            (
                key,
                re.compile(pattern + r"(?!\d|\.\d|\s?\+)"),
                shipped,
                pins[key]["version"],
            )
        )

    findings: list[Finding] = []
    scanned = 0

    def scan(file: str, line: int, text: str) -> None:
        for key, rx, shipped, raw in rules:
            for m in rx.finditer(text):
                if _HISTORICAL.search(text[max(0, m.start() - 16) : m.start()]):
                    continue
                label = _numeric(m.group(1))
                scanned_hit = label and shipped[: len(label)] == label
                if not scanned_hit:
                    findings.append(
                        Finding(
                            file,
                            "version",
                            f"line {line}: {m.group(0).strip()!r} but versions.json pins "
                            f"{key} {raw}",
                        )
                    )

    for svg in diagram_files(root):
        scanned += 1
        for line, text, _ in svg_texts(_read(svg)):
            scan(_rel(svg, root), line, text)
    for page in doc_pages(root, manifest.get("version_exclude", [])):
        scanned += 1
        for n, text in enumerate(_read(page).splitlines(), 1):
            scan(_rel(page, root), n, text)
    if not scanned:
        raise CheckError("version check found no docs files to scan")
    return findings


# ------------------------------------------------------------------ inventory


def _compose_services(root: pathlib.Path) -> list[str]:
    path = root / "docker-compose.yml"
    out, inside = [], False
    for raw in _read(path).splitlines():
        if re.match(r"^services:\s*$", raw):
            inside = True
        elif inside and re.match(r"^\S", raw) and not raw.startswith("#"):
            break
        elif inside and (m := re.match(r"^  ([A-Za-z0-9][\w.-]*):\s*$", raw)):
            out.append(m.group(1))
    return out


def _chart_workloads(root: pathlib.Path) -> list[str]:
    names: set[str] = set()
    for chart in ("spatiumddi", "spatiumddi-appliance"):
        for tpl in sorted((root / "charts" / chart / "templates").glob("*.yaml")):
            lines = _read(tpl).splitlines()
            for i, raw in enumerate(lines):
                if not re.match(
                    r"^kind:\s*(Deployment|StatefulSet|DaemonSet)\s*$", raw
                ):
                    continue
                name = ""
                for nxt in lines[i + 1 : i + 12]:
                    if m := re.match(r"^  name:\s*(.+?)\s*$", nxt):
                        name = re.sub(r"\{\{.*?\}\}", "", m.group(1)).strip("-\"' ")
                        break
                names.add(name or tpl.stem)
    return sorted(names)


def _subdirs(path: pathlib.Path) -> list[str]:
    if not path.is_dir():
        raise CheckError(f"{path} is missing")
    return sorted(
        p.name
        for p in path.iterdir()
        if p.is_dir() and not p.name.startswith((".", "_"))
    )


def _driver_modules(path: pathlib.Path) -> list[str]:
    if not path.is_dir():
        raise CheckError(f"{path} is missing")
    skip = {"base", "registry"}
    return sorted(
        p.stem
        for p in path.glob("*.py")
        if not p.stem.startswith("_") and p.stem not in skip
    )


def _integration_modules(root: pathlib.Path) -> list[str]:
    src = _read(root / "backend/app/services/feature_modules.py")
    return sorted(set(re.findall(r'id="integrations\.(\w+)"', src)))


def inventory(root: pathlib.Path) -> dict[str, str]:
    """key -> default needle."""
    items: dict[str, str] = {}
    for n in _compose_services(root):
        items[f"compose:{n}"] = n
    for n in _chart_workloads(root):
        items[f"workload:{n}"] = n
    for n in _subdirs(root / "agent"):
        items[f"agent:{n}"] = n
    for n in _driver_modules(root / "backend/app/drivers/dns"):
        items[f"dns-driver:{n}"] = n
    for n in _driver_modules(root / "backend/app/drivers/dhcp"):
        items[f"dhcp-driver:{n}"] = n
    for n in _integration_modules(root):
        items[f"integration:{n}"] = n
    return items


def _norm(text: str) -> str:
    return " " + re.sub(r"[^a-z0-9]+", " ", text.lower()).strip() + " "


def check_inventory(root: pathlib.Path, manifest: dict) -> list[Finding]:
    diagram = manifest["architecture_diagram"]
    haystack = _norm(" ".join(t for _, t, _ in svg_texts(_read(root / diagram))))
    items = inventory(root)
    if len(items) < 10:
        raise CheckError(f"inventory found only {len(items)} items; a source has moved")
    needles = manifest.get("needles", {})
    allow = manifest.get("inventory_allowlist", {})
    groups = manifest.get("inventory_groups", {})
    findings: list[Finding] = []
    for key, default in items.items():
        if key in allow:
            continue
        terms = needles.get(key) or [default]
        group_terms = groups.get(key.split(":")[0], [])
        if any(_norm(t) in haystack for t in [*terms, *group_terms]):
            continue
        findings.append(
            Finding(
                diagram,
                "inventory",
                f"{key} is shipped but not named in the diagram "
                f"(looked for {', '.join(repr(t) for t in terms)})",
            )
        )
    stale = sorted(set(allow) - set(items))
    for key in stale:
        findings.append(
            Finding(
                MANIFEST_NAME,
                "inventory",
                f"allowlist entry {key!r} matches nothing shipped",
            )
        )
    return findings


# ----------------------------------------------------------------- identifier


def model_identifiers(paths: Iterable[pathlib.Path]) -> tuple[set[str], set[str]]:
    """(all names, class names) defined across the given modules."""
    names: set[str] = set()
    classes: set[str] = set()
    for path in paths:
        tree = ast.parse(_read(path), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                names.add(node.name)
                classes.add(node.name)
                for stmt in node.body:
                    if isinstance(stmt, ast.AnnAssign) and isinstance(
                        stmt.target, ast.Name
                    ):
                        names.add(stmt.target.id)
                    elif isinstance(stmt, ast.Assign):
                        names.update(
                            t.id for t in stmt.targets if isinstance(t, ast.Name)
                        )
            elif isinstance(node, ast.Constant) and isinstance(node.value, str):
                if re.fullmatch(r"[A-Za-z_]\w{1,79}", node.value):
                    names.add(node.value)  # __tablename__, Column("x"), "uq_..." names
            elif isinstance(node, ast.Call):
                for kw in node.keywords:
                    if kw.arg:
                        names.add(kw.arg)
    return names, classes


_SNAKE = re.compile(r"(?<![\w/.\-@#$])([a-z][a-z0-9]*(?:_[a-z0-9]+)+)(?![\w/\-])")
_CAMEL = re.compile(
    r"(?<![\w/.\-@#$])([A-Z][A-Za-z0-9]*[a-z][A-Za-z0-9]*[A-Z][A-Za-z0-9]*|[A-Z]{2,}[A-Z][a-z]\w*)(?![\w/\-])"
)


def code_identifiers(text: str) -> set[str]:
    """snake_case and multi-hump CamelCase tokens; env vars and acronyms are not model names.

    Single lowercase words (``state``, ``root``) are deliberately not checked: in a
    monospace label they are as likely a DNS label or a JSON key as a column, and
    matching them would bury the findings that matter.
    """
    found = set(_SNAKE.findall(text)) | set(_CAMEL.findall(text))
    return {tok for tok in found if not tok.isupper()}


def check_identifiers(root: pathlib.Path, manifest: dict) -> list[Finding]:
    ignore = set(manifest.get("identifier_ignore", {}))
    findings: list[Finding] = []
    mapped = manifest.get("identifier_diagrams", {})
    for diagram, modules in sorted(mapped.items()):
        svg = root / diagram
        if not svg.exists():
            findings.append(
                Finding(
                    MANIFEST_NAME, "identifier", f"mapped diagram {diagram} is gone"
                )
            )
            continue
        files: list[pathlib.Path] = []
        for mod in modules:
            p = root / mod
            if not p.exists():
                raise CheckError(f"{diagram}: mapped module {mod} does not exist")
            files.append(p)
        names, classes = model_identifiers(files)
        if not names:
            raise CheckError(f"{diagram}: no identifiers parsed from {modules}")
        seen: set[str] = set()
        for line, text, _ in svg_texts(_read(svg)):
            for tok in sorted(code_identifiers(text)):
                if tok in seen or tok in ignore:
                    continue
                seen.add(tok)
                if tok in names or any(c.endswith(tok) for c in classes):
                    continue
                findings.append(
                    Finding(
                        diagram,
                        "identifier",
                        f"line {line}: {tok!r} is not a class, table, column or constraint in "
                        f"{', '.join(modules)}",
                    )
                )
    return findings


# ----------------------------------------------------------------------- path

_PATH_EXT = r"(?:py|ya?ml|sh|json|md|toml|conf|cfg|ts|tsx|j2|jinja2|nft|svg)"


def _all_basenames(root: pathlib.Path) -> set[str]:
    out = set()
    for p in root.rglob("*"):
        if p.is_file() and not (set(p.relative_to(root).parts) & _SKIP_DIRS):
            out.add(p.name)
    return out


def check_paths(root: pathlib.Path, manifest: dict) -> list[Finding]:
    roots = tuple(manifest["path_roots"])
    alt = "|".join(map(re.escape, roots))
    rooted = re.compile(r"(?<![\w/.\-])((?:" + alt + r")/[\w./\-]*[\w/\-])")
    bare = re.compile(
        r"(?<![\w/.\-])([\w\-]+(?:\.[\w\-]+)*\." + _PATH_EXT + r")(?![\w\-])"
    )
    basenames: set[str] | None = None
    findings: list[Finding] = []
    for svg in diagram_files(root):
        rel = _rel(svg, root)
        seen: set[str] = set()
        for line, text, _ in svg_texts(_read(svg)):
            for m in rooted.finditer(text):
                tok = m.group(1).rstrip("/.")
                if tok in seen or any(c in tok for c in "*{<…"):
                    continue
                seen.add(tok)
                # "k8s/README" is shorthand for k8s/README.md.
                if not (root / tok).exists() and not any(
                    (root / tok).parent.glob(pathlib.PurePosixPath(tok).name + ".*")
                ):
                    findings.append(
                        Finding(rel, "path", f"line {line}: {tok} does not exist")
                    )
            for m in bare.finditer(text):
                tok = m.group(1)
                if tok in seen or "/" in text[max(0, m.start() - 1) : m.start()]:
                    continue
                seen.add(tok)
                if basenames is None:
                    basenames = _all_basenames(root)
                if tok not in basenames:
                    findings.append(
                        Finding(rel, "path", f"line {line}: file {tok} does not exist")
                    )
    return findings


# ----------------------------------------------------------------------- main

CHECKS = {
    "version": check_versions,
    "inventory": check_inventory,
    "identifier": check_identifiers,
    "path": check_paths,
}


def run(root: pathlib.Path) -> list[Finding]:
    manifest = load_manifest(root)
    findings: list[Finding] = []
    for fn in CHECKS.values():
        findings.extend(fn(root, manifest))
    return findings


def markdown(findings: list[Finding]) -> str:
    lines = [
        MARKER,
        "",
        f"The weekly docs drift check found {len(findings)} place(s) where a diagram or doc "
        "page no longer matches the code. Reproduce locally with `make docs-drift`.",
        "",
    ]
    for kind in CHECKS:
        group = [f for f in findings if f.kind == kind]
        if not group:
            continue
        lines += [f"### {kind} ({len(group)})", ""]
        lines += [f"- `{f.file}` — {f.message}" for f in group]
        lines.append("")
    lines += [
        "---",
        "A finding is fixed in the diagram, or -- when the thing legitimately does not belong "
        "in it -- allowlisted with a reason in `scripts/docs_drift_manifest.json`. "
        "This issue auto-closes when a weekly run comes back clean.",
    ]
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument(
        "--markdown", action="store_true", help="emit the tracking-issue body"
    )
    parser.add_argument(
        "--root", type=pathlib.Path, default=REPO_ROOT, help=argparse.SUPPRESS
    )
    args = parser.parse_args(argv)
    try:
        findings = run(args.root.resolve())
    except CheckError as exc:
        print(f"lint_docs_drift: cannot run: {exc}", file=sys.stderr)
        return 2
    if args.markdown:
        if findings:
            print(markdown(findings), end="")
    else:
        for f in findings:
            print(f.line())
        print(f"{len(findings)} finding(s)", file=sys.stderr)
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
