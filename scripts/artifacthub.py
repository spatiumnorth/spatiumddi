#!/usr/bin/env python3
"""Keep the Artifact Hub annotations in charts/spatiumddi/Chart.yaml honest (#3858).

Artifact Hub reads ``artifacthub.io/*`` annotations from Chart.yaml. Two of them
change per release and one must track the shipped image list, so they sit
between generated-block markers:

  ``artifacthub.io/images``     one entry per image in ``.github/images.json``
  ``artifacthub.io/prerelease`` true for a ``-rc.N`` / ``-beta.N`` tag
  ``artifacthub.io/changes``    a pointer at the GitHub release notes

Subcommands:
  check               fail when the committed images block names a different
                      image set than .github/images.json (run by charts-lint)
  render VERSION      rewrite the block in place for a release; release.yml
                      calls it before ``helm package``

Pure stdlib, no network.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CHART = ROOT / "charts" / "spatiumddi" / "Chart.yaml"
IMAGES = ROOT / ".github" / "images.json"
BEGIN = "  # artifacthub:generated:begin"
END = "  # artifacthub:generated:end"
REGISTRY = "ghcr.io/spatiumnorth"
RELEASES = "https://github.com/spatiumnorth/spatiumddi/releases"


def image_names() -> list[str]:
    return [e["image"] for e in json.loads(IMAGES.read_text())]


def block(version: str) -> str:
    # A tag that is not a release (``latest``, a nightly) is never flagged
    # prerelease on its own say-so; only a SemVer pre-release tag is.
    prerelease = "-" in version and re.match(r"^\d+\.\d+\.\d+-", version) is not None
    lines = [BEGIN, "  artifacthub.io/images: |"]
    for name in image_names():
        lines += [f"    - name: {name}", f"      image: {REGISTRY}/{name}:{version}"]
    lines += [
        f'  artifacthub.io/prerelease: "{"true" if prerelease else "false"}"',
        "  artifacthub.io/changes: |",
        "    - kind: changed",
        f'      description: "See the release notes for {version}"',
        "      links:",
        "        - name: Release notes",
        f"          url: {RELEASES}/tag/{version}",
        END,
    ]
    return "\n".join(lines)


def split(text: str) -> tuple[str, str, str]:
    i, j = text.find(BEGIN), text.find(END)
    if i < 0 or j < i:
        sys.exit(f"{CHART}: artifacthub:generated markers missing")
    return text[:i], text[i : j + len(END)], text[j + len(END) :]


def main(argv: list[str]) -> int:
    text = CHART.read_text()
    head, cur, tail = split(text)
    if argv[:1] == ["check"]:
        have = re.findall(r"^\s+- name: (\S+)$", cur.split("prerelease")[0], re.M)
        if have != image_names():
            print(f"artifacthub.io/images {have} != .github/images.json {image_names()}")
            print("run: python3 scripts/artifacthub.py render latest")
            return 1
        print("artifacthub annotations: images in step with .github/images.json")
        return 0
    if len(argv) == 2 and argv[0] == "render":
        CHART.write_text(head + block(argv[1]) + tail)
        return 0
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
