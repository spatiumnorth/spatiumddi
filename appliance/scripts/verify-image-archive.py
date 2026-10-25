#!/usr/bin/env python3
"""Check that a ``docker save`` tar (read from stdin) really holds an image.

#2393: with Docker's containerd image store, a platform-less
``docker save`` of a freshly pulled multi-arch image can write the index
and manifests but NO config and NO layers. The bake reported success, the
appliance's k3s imported the index, and containerd then tried to pull the
image at pod start, which fails on an air-gapped box.

Usage:  zstd -dc image.tar.zst | verify-image-archive.py --platform linux/amd64 --name IMG

Exit 0 when the archive carries the config blob and every layer blob of
the manifest for the target platform; exit 1, naming the image and the
missing blob, otherwise. Handles both the OCI layout (``index.json`` +
``blobs/sha256/``) and the classic ``manifest.json`` layout. Streams the
tar once; only small JSON members are held in memory.
"""

from __future__ import annotations

import argparse
import json
import sys
import tarfile

#: Manifests and indexes are KBs. Anything bigger is a layer, never read.
_JSON_LIMIT = 4 * 1024 * 1024

_INDEX_TYPES = (
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
)


def _blob(digest: str) -> str:
    algo, _, hexd = digest.partition(":")
    return f"blobs/{algo}/{hexd}"


def read_archive(fh) -> tuple[set[str], dict[str, bytes]]:
    names: set[str] = set()
    small: dict[str, bytes] = {}
    with tarfile.open(fileobj=fh, mode="r|") as tf:
        for m in tf:
            name = m.name.lstrip("./")
            names.add(name)
            if m.isfile() and m.size <= _JSON_LIMIT:
                f = tf.extractfile(m)
                if f is not None:
                    small[name] = f.read()
    return names, small


def check_manifest(doc: dict, names: set[str], where: str) -> list[str]:
    problems = []
    cfg = (doc.get("config") or {}).get("digest")
    if not cfg:
        problems.append(f"{where}: manifest has no config digest")
    elif _blob(cfg) not in names:
        problems.append(f"{where}: config blob {cfg} is missing")
    for layer in doc.get("layers") or []:
        d = layer.get("digest", "")
        if _blob(d) not in names:
            problems.append(f"{where}: layer blob {d} is missing")
    return problems


def check_descriptor(desc, names, small, platform, where, depth=0) -> list[str]:
    digest = desc.get("digest", "")
    path = _blob(digest)
    if path not in small:
        return [f"{where}: blob {digest} is missing"]
    try:
        doc = json.loads(small[path])
    except ValueError:
        return [f"{where}: blob {digest} is not valid JSON"]
    mt = desc.get("mediaType") or doc.get("mediaType") or ""
    if mt in _INDEX_TYPES or "manifests" in doc:
        if depth > 3:
            return [f"{where}: index nesting too deep"]
        want_os, _, want_arch = platform.partition("/")
        matched = [
            d
            for d in doc.get("manifests") or []
            if (d.get("platform") or {}).get("os") == want_os
            and (d.get("platform") or {}).get("architecture") == want_arch
        ]
        if not matched:
            return [f"{where}: index lists no manifest for {platform}"]
        problems: list[str] = []
        for d in matched:
            problems += check_descriptor(d, names, small, platform, where, depth + 1)
        return problems
    return check_manifest(doc, names, where)


def verify(names, small, platform, name) -> list[str]:
    if "index.json" in small:
        idx = json.loads(small["index.json"])
        descs = idx.get("manifests") or []
        if not descs:
            return [f"{name}: index.json lists no manifests"]
        problems: list[str] = []
        for d in descs:
            problems += check_descriptor(d, names, small, platform, name)
        return problems
    if "manifest.json" in small:
        entries = json.loads(small["manifest.json"])
        if not entries:
            return [f"{name}: manifest.json is empty"]
        problems = []
        for e in entries:
            for p in [e.get("Config", "")] + list(e.get("Layers") or []):
                if p not in names:
                    problems.append(f"{name}: {p} is missing")
        return problems
    return [f"{name}: archive has neither index.json nor manifest.json"]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--platform", required=True)
    ap.add_argument("--name", required=True)
    args = ap.parse_args()
    try:
        names, small = read_archive(sys.stdin.buffer)
        problems = verify(names, small, args.platform, args.name)
    except (tarfile.TarError, ValueError) as exc:
        problems = [f"{args.name}: unreadable archive ({exc})"]
    if problems:
        print(
            f"ERROR: baked archive for {args.name} is incomplete "
            f"(platform {args.platform}):",
            file=sys.stderr,
        )
        for p in problems:
            print(f"         {p}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
