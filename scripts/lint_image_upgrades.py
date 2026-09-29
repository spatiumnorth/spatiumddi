#!/usr/bin/env python3
"""Refuse a shipped image whose package layer can never be patched (#1088).

Every image the nightly and release workflows publish is built from a base
image somebody else maintains. Two things have to be true for a distro
security fix to actually reach it, and BOTH failed silently on the api image
for as long as it has existed:

  1. The Dockerfile must UPGRADE the base image's own packages. Installing a
     package list patches only what is on that list — ``perl-base``, ``gzip``,
     ``libpcre2``, ``libsqlite3`` came with ``python:3.12-slim`` and could
     only ever be fixed by upstream rebuilding it, which is not a schedule we
     control. The nightly of 2026-09-14 refused to publish the api image on
     34 HIGH/CRITICAL findings whose fixes had been on deb.debian.org for
     days.

  2. The upgrade must be able to RUN. BuildKit keys a layer on its RUN text,
     so a ``type=gha`` cache serves the whole layer — package set included —
     from whenever it was first built, until that text changes. An upgrade
     line that never executes is indistinguishable, in the built image, from
     no upgrade line at all. The Alpine images solve this with an
     ``ARG APK_SNAPSHOT`` the nightly passes its date tag to; the Debian ones
     use ``ARG APT_SNAPSHOT``. An image declaring neither ignores both build
     args without a word — which is how the same nightly reported ``perl`` at
     5.40.1-6 while the index had offered 5.40.1-6+deb13u1 for days.

Neither failure announces itself: the build is green, the image is published,
and the only symptom is a Trivy report weeks later blaming packages nobody
touched. So this asserts both, over the SAME image list the nightly matrix
builds from — a new image is covered the moment it is added there, rather
than when somebody remembers to add it here.

It also asserts that release.yml publishes exactly that list (#1226). The
release workflow carries its own copy because it builds, scans and pushes
from it; an image missing from that copy would keep building every night
and silently stop being released.

stdlib-only, no network, no docker. Exit 1 on any finding.
"""

from __future__ import annotations

import json
import pathlib
import re
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
NIGHTLY = REPO_ROOT / ".github" / "workflows" / "nightly.yml"
RELEASE = REPO_ROOT / ".github" / "workflows" / "release.yml"

# The images list is a heredoc of JSON inside a step of each workflow (the
# nightly's gate, the release's meta). Parsed rather than duplicated, so this
# linter cannot fall behind the matrix.
_IMAGES_BLOCK = re.compile(
    r"cat > /tmp/images\.json <<'IMAGES_EOF'\n(.*?)\n\s*IMAGES_EOF", re.DOTALL
)

# A package-manager upgrade of everything already installed. `apt-get upgrade`
# and `apt-get dist-upgrade` both qualify; `apt-get install` deliberately does
# not — that is the half that was already there and was not enough.
_UPGRADES = (
    re.compile(r"\bapk\s+upgrade\b"),
    re.compile(r"\bapt-get\s+(?:-\S+\s+)*(?:dist-upgrade|upgrade)\b"),
)

# The cache-busting ARG, declared in the Dockerfile so the build arg the
# workflow passes is not silently discarded. An ARG declared but never
# referenced is equally inert, so the reference is checked too.
_SNAPSHOT_ARG = re.compile(r"^\s*ARG\s+(AP[KT]_SNAPSHOT)\b", re.MULTILINE)

# ``FROM [--platform=…] <base> [AS <name>]``.
_FROM = re.compile(
    r"^\s*FROM\s+(?:--\S+\s+)*(\S+)(?:\s+AS\s+(\S+))?\s*$", re.IGNORECASE
)


def _stages(body: str) -> list[tuple[str | None, str, list[str]]]:
    """Split a Dockerfile into ``(name, base, lines)`` per build stage."""
    stages: list[tuple[str | None, str, list[str]]] = []
    current: list[str] | None = None
    for line in body.splitlines():
        match = _FROM.match(line)
        if match:
            base, name = match.group(1), match.group(2)
            current = []
            stages.append((name.lower() if name else None, base.lower(), current))
        elif current is not None:
            current.append(line)
    return stages


def _shipped_body(body: str, target: str) -> str:
    """The instructions that actually reach the published image.

    A multi-stage Dockerfile's builder stages are DISCARDED — their
    packages never ship, and ``COPY --from`` brings files, not a package
    database. So checking the whole file passes an image whose only
    ``apk upgrade`` lives in a builder, which is not a hypothetical
    shape: it is what most of these Dockerfiles look like. The matrix
    already records each image's ``target`` (empty = the last stage, the
    Docker default), and the target's ancestry is followed because a
    stage built ``FROM`` another one does inherit its layers.
    """
    stages = _stages(body)
    if not stages:
        return ""
    by_name = {name: index for index, (name, _, _) in enumerate(stages) if name}

    if target:
        index = by_name.get(target.lower())
        if index is None:
            # Naming a stage that does not exist would make `docker build`
            # fail; reporting it is better than checking the wrong stage.
            raise KeyError(target)
    else:
        index = len(stages) - 1

    chain = [index]
    seen = {index}
    while True:
        base = stages[chain[0]][1]
        parent = by_name.get(base)
        if parent is None or parent in seen:
            break
        chain.insert(0, parent)
        seen.add(parent)
    return "\n".join("\n".join(stages[i][2]) for i in chain)


def _images(workflow: pathlib.Path) -> list[dict[str, str]]:
    match = _IMAGES_BLOCK.search(workflow.read_text())
    if not match:
        raise SystemExit(
            f"{workflow}: could not find the images.json heredoc — if the step was "
            "restructured, update this linter rather than letting it silently check nothing"
        )
    # The heredoc body is indented inside the YAML block scalar.
    body = "\n".join(line.strip() for line in match.group(1).splitlines())
    return json.loads(body)


def _list_drift(nightly: list[dict[str, str]], release: list[dict[str, str]]) -> list[str]:
    """How the release's image list differs from the nightly's, entry by entry."""
    by_name = {image["image"]: image for image in nightly}
    released = {image["image"]: image for image in release}
    findings = [
        f"{name}: built by the nightly but not published by release.yml"
        for name in sorted(by_name.keys() - released.keys())
    ]
    findings += [
        f"{name}: published by release.yml but not built by the nightly"
        for name in sorted(released.keys() - by_name.keys())
    ]
    findings += [
        f"{name}: release.yml builds {released[name]} but the nightly builds {by_name[name]}"
        for name in sorted(by_name.keys() & released.keys())
        if released[name] != by_name[name]
    ]
    return findings


def _strip_trailing_comment(line: str) -> str:
    """Drop an unquoted ``#`` comment from the end of one line.

    A trailing comment is a comment to the shell too, so ``&& apt-get
    install foo  # we do not apt-get upgrade here`` contains the phrase
    and performs none of it. Quote state is tracked because ``#`` inside
    a string is data — ``echo "a#b"`` must not be truncated to ``echo "a``.
    """
    quote: str | None = None
    index = 0
    while index < len(line):
        char = line[index]
        if quote:
            if char == "\\" and quote == '"':
                index += 1
            elif char == quote:
                quote = None
        elif char in "'\"":
            quote = char
        elif char == "#" and (index == 0 or line[index - 1].isspace()):
            return line[:index]
        index += 1
    return line


def _strip_comments(text: str) -> str:
    """Drop ``#`` comments, whole-line and trailing alike.

    These Dockerfiles carry long rationale comments that name the very
    commands being looked for (``apk upgrade``, ``APK_SNAPSHOT``), so matching
    against the raw text would pass an image whose comments merely DESCRIBE an
    upgrade it does not perform — in either position.
    """
    return "\n".join(
        _strip_trailing_comment(line)
        for line in text.splitlines()
        if not line.lstrip().startswith("#")
    )


def main() -> int:
    findings: list[str] = _list_drift(_images(NIGHTLY), _images(RELEASE))

    for image in _images(NIGHTLY):
        rel = image["file"].lstrip("./")
        path = REPO_ROOT / rel
        if not path.is_file():
            findings.append(f"{rel}: listed in the nightly matrix but not on disk")
            continue

        try:
            body = _shipped_body(_strip_comments(path.read_text()), image.get("target", ""))
        except KeyError as exc:
            findings.append(
                f"{rel} ({image['image']}): the matrix names target {exc.args[0]!r}, which "
                "this Dockerfile does not define"
            )
            continue
        if not body.strip():
            findings.append(
                f"{rel} ({image['image']}): no build stage found — if the file was "
                "restructured, update this linter rather than letting it check nothing"
            )
            continue

        if not any(pattern.search(body) for pattern in _UPGRADES):
            findings.append(
                f"{rel} ({image['image']}): no `apk upgrade` / `apt-get upgrade` — the base "
                "image's own packages can never be patched by this build"
            )

        declared = {m.group(1) for m in _SNAPSHOT_ARG.finditer(body)}
        if not declared:
            findings.append(
                f"{rel} ({image['image']}): declares no ARG APK_SNAPSHOT / APT_SNAPSHOT — "
                "the nightly's cache will serve a frozen package layer and the upgrade "
                "above will not run"
            )
        else:
            for name in sorted(declared):
                # `ARG X` with no `${X}` in the RUN text does not change the
                # layer's cache key, so it busts nothing.
                if f"${{{name}}}" not in body and f"${name}" not in body:
                    findings.append(
                        f"{rel} ({image['image']}): ARG {name} is declared but never "
                        "referenced, so it does not change the RUN text and busts no cache"
                    )

    if findings:
        print("Shipped-image package-upgrade linter — findings:\n", file=sys.stderr)
        for finding in findings:
            print(f"  ✗ {finding}", file=sys.stderr)
        print(
            "\nSee scripts/lint_image_upgrades.py for why each of these is silent.",
            file=sys.stderr,
        )
        return 1

    print("✓ every shipped image upgrades its packages behind a cache-busting snapshot ARG")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
