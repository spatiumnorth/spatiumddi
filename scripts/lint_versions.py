#!/usr/bin/env python3
"""Guard the version pins Dependabot cannot see (#975).

``versions.json`` at the repo root is the source of truth for every pin that
is not owned by a lockfile or by Dependabot. This script is what makes it a
source of truth rather than a second copy: it asserts that every ``match``
template in the manifest still appears in its file, the expected number of
times, at the version the manifest declares.

Two modes:

``--check`` (the default)
    Offline, stdlib-only, no network. Runs in CI's unconditional Backend Lint
    job. Exit 0 when every pin agrees with the manifest, 1 otherwise.

``--check-upstream``
    Resolves each component's declared upstream and prints a current-vs-latest
    table. **Advisory** -- it exits 0 even when things are behind, because a
    deliberate hold is not a failure and a network hiccup must not be one
    either. The weekly job turns its output into a tracking issue.

Failure semantics, because this repo has been bitten four separate times by a
guard that reported success while evaluating nothing (#1028, #1029, #1030,
and the ``previous.json`` rotation in #882):

* A manifest that is missing, unparseable, or has no components is a hard
  error -- never "nothing to check, all good".
* A ``pinned_in`` path that does not exist is an ERROR, not a skip. A pin
  whose file was renamed is precisely the drift this exists to catch, and
  skipping it would report the rename as a pass.
* ``--check`` refuses to report success unless it actually compared at least
  one assertion, and prints the number it made so "0 checked" cannot read the
  same as "all passed".
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
import sys
from typing import Any

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
MANIFEST_PATH = REPO_ROOT / "versions.json"


class ManifestError(Exception):
    """The manifest itself is unusable -- distinct from a pin being wrong."""


#: Exhaustive key sets. Anything outside them is a typo, and a typo in this
#: file is a guard that silently stops guarding -- see load_manifest.
_MANIFEST_KEYS = {"$comment", "components", "holds"}
_COMPONENT_KEYS = {"version", "digest", "pinned_in", "upstream", "hold", "note"}
_SITE_KEYS = {"path", "match", "count"}


# ── manifest loading ─────────────────────────────────────────────────────────


def load_manifest(path: pathlib.Path) -> dict[str, Any]:
    if not path.is_file():
        raise ManifestError(f"{path} does not exist")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ManifestError(f"{path} is not valid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise ManifestError(f"{path} must contain a JSON object")

    components = data.get("components")
    if not isinstance(components, dict) or not components:
        raise ManifestError(f"{path} declares no components — nothing would be checked")

    unknown_top = set(data) - _MANIFEST_KEYS
    if unknown_top:
        raise ManifestError(f"unknown top-level key(s): {sorted(unknown_top)}")

    for name, entry in components.items():
        if not isinstance(entry, dict):
            raise ManifestError(f"component {name!r} is not an object")
        # Unknown keys are REFUSED, not ignored. A typo is otherwise silent
        # and strictly weakening: ``"counts": 3`` leaves ``count`` unset, so
        # the exact-occurrence assertion quietly downgrades to "at least one"
        # and a 2-of-3 partial bump passes. Same failure shape the manifest
        # exists to prevent, one level up.
        unknown = set(entry) - _COMPONENT_KEYS
        if unknown:
            raise ManifestError(
                f"component {name!r} has unknown key(s): {sorted(unknown)} "
                f"(allowed: {sorted(_COMPONENT_KEYS)})"
            )
        version = entry.get("version")
        if not isinstance(version, str) or not version.strip():
            raise ManifestError(f"component {name!r} has no version")
        pinned_in = entry.get("pinned_in")
        if not isinstance(pinned_in, list) or not pinned_in:
            # A component with nowhere to check is a documentation entry
            # wearing a component's clothes. Those belong under "holds", which
            # is honest about asserting nothing.
            raise ManifestError(
                f"component {name!r} has an empty pinned_in — "
                f"move it to the top-level 'holds' list if it asserts nothing"
            )
        for site in pinned_in:
            if not isinstance(site, dict) or not isinstance(site.get("path"), str):
                raise ManifestError(f"component {name!r} has a pinned_in entry with no path")
            unknown = set(site) - _SITE_KEYS
            if unknown:
                raise ManifestError(
                    f"component {name!r} site {site['path']!r} has unknown key(s): "
                    f"{sorted(unknown)} (allowed: {sorted(_SITE_KEYS)})"
                )
            count = site.get("count")
            if count is not None and (not isinstance(count, int) or count < 1):
                raise ManifestError(
                    f"component {name!r} site {site['path']!r}: "
                    f"count must be a positive integer, got {count!r}"
                )
    return data


def render_match(template: str, version: str) -> str:
    """Substitute the version placeholders in a match template.

    ``{version}`` is the canonical string; ``{version_no_v}`` is the same with
    a leading ``v`` stripped, which is what image tags and chart dependency
    versions use where the release tag carries one (``v3.21.4`` -> ``3.21.4``).
    """
    return template.format(version=version, version_no_v=version.lstrip("v"))


# ── the offline check ────────────────────────────────────────────────────────


def check(manifest: dict[str, Any], root: pathlib.Path) -> tuple[list[str], int]:
    """Return (problems, number of assertions actually made)."""
    problems: list[str] = []
    checked = 0

    for name, entry in manifest["components"].items():
        version = entry["version"]
        # A digest pin is asserted as a literal in every file that carries the
        # tag. It cannot be a template -- a digest does not derive from a
        # version -- so ``--check-upstream`` is what proves the PAIR still
        # agrees; this only stops the literal being edited to something the
        # files do not contain.
        digest = entry.get("digest")
        if digest is not None:
            checked += 1
            first = manifest["components"][name]["pinned_in"][0]["path"]
            path = root / first
            if not path.is_file():
                problems.append(f"{name}: {first} does not exist (pinned_in is stale)")
            elif digest not in path.read_text(encoding="utf-8", errors="replace"):
                problems.append(
                    f"{name}: {first} does not contain digest {digest!r} "
                    f"(manifest pins {name} {version} at that digest)"
                )
        for site in entry["pinned_in"]:
            rel = site["path"]
            template = site.get("match", "{version}")
            expected = site.get("count")
            path = root / rel

            try:
                needle = render_match(template, version)
            except (KeyError, IndexError, ValueError) as exc:
                problems.append(
                    f"{name}: match template {template!r} is not a valid "
                    f"version template ({exc})"
                )
                continue

            checked += 1

            if not path.is_file():
                # Deliberately an error, not a skip: a pin whose file moved is
                # the drift this guard exists for.
                problems.append(f"{name}: {rel} does not exist (pinned_in is stale)")
                continue

            found = path.read_text(encoding="utf-8", errors="replace").count(needle)
            if expected is None:
                if found < 1:
                    problems.append(
                        f"{name}: {rel} does not contain {needle!r} "
                        f"(manifest says {name} is {version})"
                    )
            elif found != expected:
                problems.append(
                    f"{name}: {rel} contains {needle!r} {found}×, expected {expected}× "
                    f"(manifest says {name} is {version})"
                )

    return problems, checked


# ── the upstream check (advisory, network) ───────────────────────────────────


#: Hosts this script is allowed to talk to. Every URL it builds is composed
#: from a literal here plus a repo name out of the manifest, so the set is
#: closed; asserting it anyway keeps a malformed ``upstream.repo`` from
#: steering a request somewhere else.
_ALLOWED_HOSTS = frozenset(
    {"api.github.com", "hub.docker.com", "quay.io", "rubygems.org", "dl-cdn.alpinelinux.org"}
)

#: The one host that gets the token.
_GITHUB_API_HOST = "api.github.com"


def _http_bytes(url: str, token: str | None = None) -> bytes:
    import urllib.parse
    import urllib.request

    parts = urllib.parse.urlsplit(url)
    # Compare the parsed HOSTNAME, never a substring of the URL. ``"api.
    # github.com" in url`` is also true for ``https://evil.example/api.
    # github.com/x`` — which would send the token to whoever owns that host.
    # (CodeQL: incomplete URL substring sanitization.)
    host = (parts.hostname or "").lower()
    if parts.scheme != "https" or host not in _ALLOWED_HOSTS:
        raise LookupError(f"refusing to fetch {url!r}: not an allowed https endpoint")

    req = urllib.request.Request(url, headers={"User-Agent": "spatiumddi-lint-versions"})
    if token and host == _GITHUB_API_HOST:
        req.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(req, timeout=20) as resp:  # noqa: S310 — https + allowlist above
        data: bytes = resp.read()
        return data


def _http_json(url: str, token: str | None = None) -> Any:
    return json.loads(_http_bytes(url, token).decode("utf-8"))


def _latest_github(repo: str, track: str | None, token: str | None) -> str:
    if not track:
        return str(_http_json(f"https://api.github.com/repos/{repo}/releases/latest", token)["tag_name"])
    pattern = re.compile(track)
    rel = _http_json(f"https://api.github.com/repos/{repo}/releases?per_page=100", token)
    for entry in rel:
        tag = str(entry.get("tag_name", ""))
        if pattern.search(tag) and not entry.get("prerelease"):
            return tag
    raise LookupError(f"no release on {repo} matching {track!r}")


def _latest_tag(tags: list[str], track: str | None) -> str:
    """Newest tag by natural version order, optionally filtered by a regex."""
    pattern = re.compile(track) if track else None
    candidates = [t for t in tags if pattern is None or pattern.search(t)]
    if not candidates:
        raise LookupError(f"no tag matching {track!r}")

    def key(tag: str) -> list[int]:
        return [int(part) for part in re.findall(r"\d+", tag)]

    return max(candidates, key=key)


def _latest_dockerhub(repo: str, track: str | None) -> str:
    tags: list[str] = []
    url = f"https://hub.docker.com/v2/repositories/{repo}/tags?page_size=100"
    for _ in range(5):  # bounded: five pages is 500 tags
        page = _http_json(url)
        tags.extend(str(t["name"]) for t in page.get("results", []))
        url = page.get("next")
        if not url:
            break
    return _latest_tag(tags, track)


def _latest_quay(repo: str, track: str | None) -> str:
    page = _http_json(
        f"https://quay.io/api/v1/repository/{repo}/tag/?limit=100&onlyActiveTags=true"
    )
    return _latest_tag([str(t["name"]) for t in page.get("tags", [])], track)


def parse_apkindex(text: str) -> dict[str, str]:
    """``{package: version}`` from an Alpine ``APKINDEX``.

    The index is blank-line-separated records of ``X:value`` lines; ``P:`` is
    the package name and ``V:`` its full version, release suffix included
    (``9.20.29-r0``). The suffix matters: a security rebuild is often only an
    ``-rN`` bump, and a floor written against ``-r0`` must see ``-r1``.
    """
    versions: dict[str, str] = {}
    for record in text.split("\n\n"):
        fields = dict(line.split(":", 1) for line in record.splitlines() if ":" in line[:2])
        name, version = fields.get("P"), fields.get("V")
        if name and version:
            versions[name] = version
    return versions


def _latest_alpine(repo: str, branch: str | None) -> str:
    """Current version of an Alpine package on the branch the images build on.

    ``repo`` is ``<repository>/<package>`` (``main/bind``). The branch is the
    manifest's own ``alpine`` component, never a second copy of it here, so
    bumping Alpine moves the lookup with it. x86_64's index is read because
    Alpine builds every architecture from the same APKBUILD at the same
    version.
    """
    import gzip
    import io
    import tarfile

    if not branch:
        raise LookupError("alpine-package upstream needs the manifest's `alpine` component")
    repository, _, package = repo.partition("/")
    if not repository or not package:
        raise LookupError(f"alpine-package repo must be <repository>/<package>, got {repo!r}")
    url = f"https://dl-cdn.alpinelinux.org/alpine/v{branch}/{repository}/x86_64/APKINDEX.tar.gz"
    blob = _http_bytes(url)
    with tarfile.open(fileobj=io.BytesIO(gzip.decompress(blob)), mode="r:") as tar:
        member = tar.extractfile("APKINDEX")
        if member is None:
            raise LookupError(f"{url} has no APKINDEX member")
        index = parse_apkindex(member.read().decode("utf-8", errors="replace"))
    if package not in index:
        raise LookupError(f"{package} is not in Alpine v{branch}/{repository}")
    return index[package]


def resolve_upstream(
    entry: dict[str, Any], token: str | None, alpine_branch: str | None = None
) -> str | None:
    """Latest upstream version, or None when the entry declares no upstream."""
    upstream = entry.get("upstream") or {}
    kind = upstream.get("kind", "none")
    track = upstream.get("track")
    if kind == "none":
        return None
    if kind == "alpine-package":
        return _latest_alpine(upstream["repo"], alpine_branch)
    if kind == "github-release":
        return _latest_github(upstream["repo"], track, token)
    if kind == "dockerhub":
        return _latest_dockerhub(upstream["repo"], track)
    if kind == "quay":
        return _latest_quay(upstream["repo"], track)
    if kind == "rubygems":
        return str(_http_json(f"https://rubygems.org/api/v1/versions/{upstream['repo']}/latest.json")["version"])
    raise LookupError(f"unknown upstream kind {kind!r}")


def _comparable(value: str) -> str:
    """Reduce a version string to the part worth comparing.

    Upstream and the pin rarely spell a version the same way: a chart release
    is tagged ``metallb-chart-0.16.1`` against a pin of ``v0.15.3``, k3s tags
    ``v1.36.4+k3s1``, and an image tag carries a base-OS suffix
    (``8.10.1-alpine``). So take the LAST dotted number run, which is the
    version in every one of those shapes.

    "Last" and "dotted" are both load-bearing: ``frr-k8s-chart-0.0.26``
    contains a bare ``8`` inside "k8s", and a first-match or any-digits rule
    would compare that against the real version and report a wrong verdict.
    Tags with no dotted run (``16-alpine``) fall back to their digits, and
    ones with no digits at all (``latest``) compare as themselves.
    """
    dotted = re.findall(r"\d+(?:\.\d+)+", value)
    if dotted:
        return dotted[-1]
    digits = re.findall(r"\d+", value)
    return digits[-1] if digits else value


def _version_key(value: str) -> tuple[int, ...] | None:
    """An orderable key for the version ``_comparable`` extracts, or None.

    An Alpine release suffix (``-r3``) is kept as a last component, so
    ``9.20.29-r1`` orders after ``9.20.29-r0``. None when there is no number
    to order by (``latest``).
    """
    match = None
    for match in re.finditer(r"(\d+(?:\.\d+)+)(?:-r(\d+))?", value):
        pass
    if match is not None:
        return (*(int(p) for p in match.group(1).split(".")), int(match.group(2) or 0))
    digits = re.findall(r"\d+", value)
    return (int(digits[-1]),) if digits else None


def is_behind(latest: str, current: str) -> bool:
    """True when upstream is NEWER than the pin.

    Not "different": a pin can be ahead of what an upstream query returns (a
    release published to npm but not as a GitHub release, say), and reporting
    that as "behind" invites a downgrade. When either side has no number to
    order by, fall back to "differs", which is all that can be said.
    """
    latest_key, current_key = _version_key(latest), _version_key(current)
    if latest_key is None or current_key is None:
        return _comparable(latest) != _comparable(current)
    return latest_key > current_key


def _dockerhub_tag_digest(repo: str, tag: str) -> str:
    return str(_http_json(f"https://hub.docker.com/v2/repositories/{repo}/tags/{tag}")["digest"])


def check_upstream(manifest: dict[str, Any], token: str | None) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    # Alpine-packaged daemons are looked up on the branch the images build on.
    alpine_branch = (manifest["components"].get("alpine") or {}).get("version")
    for name, entry in manifest["components"].items():
        row: dict[str, Any] = {
            "name": name,
            "current": entry["version"],
            "hold": entry.get("hold"),
            "latest": None,
            "error": None,
            "behind": False,
            "digest_mismatch": False,
        }
        try:
            latest = resolve_upstream(entry, token, alpine_branch)
        except Exception as exc:  # noqa: BLE001 — advisory; one failure must not stop the sweep
            row["error"] = f"{type(exc).__name__}: {exc}"
        else:
            row["latest"] = latest
            if latest is not None:
                row["behind"] = is_behind(latest, entry["version"])

        # A digest-pinned component has TWO ways to be wrong, and the offline
        # lint can only see one: bumping `version` while leaving `digest`
        # alone passes every literal assertion and still builds the OLD image.
        # This is where that is caught.
        digest = entry.get("digest")
        upstream = entry.get("upstream") or {}
        if digest and upstream.get("kind") == "dockerhub" and not row["error"]:
            try:
                actual = _dockerhub_tag_digest(upstream["repo"], entry["version"])
            except Exception as exc:  # noqa: BLE001 — advisory, like the lookup above
                row["error"] = f"digest check failed: {type(exc).__name__}: {exc}"
            else:
                if actual != digest:
                    row["digest_mismatch"] = True
                    row["error"] = (
                        f"digest pin does not match tag {entry['version']} upstream "
                        f"(pinned {digest[:19]}…, upstream {actual[:19]}…) — "
                        f"bump `digest` alongside `version`"
                    )
        rows.append(row)
    return rows


def format_upstream_table(rows: list[dict[str, Any]]) -> str:
    out = ["| Component | Pinned | Latest upstream | Status |", "|---|---|---|---|"]
    for row in rows:
        if row["error"]:
            status = f"⚠️ check failed — {row['error']}"
            latest = "—"
        elif row["latest"] is None:
            status = "— no upstream declared"
            latest = "—"
        elif row["behind"] and row["hold"]:
            status = "🔒 behind, held on purpose"
            latest = row["latest"]
        elif row["behind"]:
            status = "⬆️ behind"
            latest = row["latest"]
        else:
            status = "✅ current"
            latest = row["latest"]
        out.append(f"| `{row['name']}` | `{row['current']}` | `{latest}` | {status} |")
    return "\n".join(out)


# ── entry point ──────────────────────────────────────────────────────────────


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__.splitlines()[0],
        # Without this, argparse resolves any unambiguous PREFIX of a long
        # option -- so ``--check``, the mode this script's own docstring
        # documents, silently became ``--check-upstream``: the advisory
        # network mode that always exits 0. Following the documentation
        # turned the guard off. ``--check`` is now a real flag, and any
        # other undefined option is an error instead of a near-miss.
        allow_abbrev=False,
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="assert every pin matches the manifest (the default; offline, no network)",
    )
    parser.add_argument(
        "--manifest",
        type=pathlib.Path,
        default=MANIFEST_PATH,
        help="path to versions.json (default: the repo root's)",
    )
    parser.add_argument(
        "--root",
        type=pathlib.Path,
        default=None,
        help="repo root the pinned_in paths are relative to (default: the manifest's directory)",
    )
    parser.add_argument(
        "--check-upstream",
        action="store_true",
        help="resolve each upstream and print a current-vs-latest table (advisory, needs network)",
    )
    parser.add_argument(
        "--github-token",
        default=None,
        help="token for api.github.com (raises the rate limit); also read from GITHUB_TOKEN",
    )
    args = parser.parse_args(argv)

    try:
        manifest = load_manifest(args.manifest)
    except ManifestError as exc:
        print(f"versions.json is unusable: {exc}", file=sys.stderr)
        return 1

    if args.check_upstream and args.check:
        print("--check and --check-upstream are different modes; pass one", file=sys.stderr)
        return 1

    if args.check_upstream:
        token = args.github_token or os.environ.get("GITHUB_TOKEN")
        rows = check_upstream(manifest, token)
        print(format_upstream_table(rows))
        behind = [r for r in rows if r["behind"] and not r["hold"]]
        held = [r for r in rows if r["behind"] and r["hold"]]
        failed = [r for r in rows if r["error"]]
        print()
        print(
            f"{len(behind)} behind upstream, {len(held)} behind but held on purpose, "
            f"{len(failed)} could not be checked, {len(rows)} components total."
        )
        # Machine-readable, because the prose line above is not. A consumer
        # scraping the first number off it reads "0 behind" when every lookup
        # failed and reports the fleet current -- the reason this line exists.
        # ``failed`` is what makes "we could not tell" distinguishable from
        # "nothing is behind"; they must never collapse into one verdict.
        print(
            f"RESULT behind={len(behind)} held={len(held)} "
            f"failed={len(failed)} total={len(rows)}"
        )
        # Advisory by design: a hold is not a failure, and neither is a
        # transient network error on a weekly informational job.
        return 0

    root = args.root or args.manifest.resolve().parent
    problems, checked = check(manifest, root)

    if checked == 0:
        # Unreachable given load_manifest's guarantees, and asserted anyway:
        # "0 assertions" must never be able to print the same line as "all
        # passed" (#1030).
        print("versions.json produced no assertions — refusing to report a pass", file=sys.stderr)
        return 1

    if problems:
        print(f"{len(problems)} version pin(s) disagree with versions.json:\n", file=sys.stderr)
        for problem in problems:
            print(f"  ✗ {problem}", file=sys.stderr)
        print(
            "\nversions.json is the source of truth. Either the file is stale "
            "(bump it) or the pin was edited without it (put it back).",
            file=sys.stderr,
        )
        return 1

    print(
        f"OK — {checked} pin assertion(s) across "
        f"{len(manifest['components'])} component(s) agree with versions.json."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
