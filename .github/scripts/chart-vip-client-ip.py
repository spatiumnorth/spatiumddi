#!/usr/bin/env python3
"""Refuse a MetalLB VIP Service that would SNAT its clients.

Reads one or more ``helm template`` streams (files, or stdin when given ``-``)
and fails for every ``type: LoadBalancer`` Service that pins a MetalLB VIP
(the ``metallb.universe.tf/loadBalancerIPs`` annotation) without
``externalTrafficPolicy: Local``.

Under the default ``Cluster`` policy kube-proxy rewrites the source address of
every packet that reaches the VIP to the node, or to the CNI gateway when the
endpoint is a pod. A service that cares who is asking then sees two or three
addresses for the whole network. For the DNS VIP that is every per-client
feature at once: the resolver's per-client rate limit throttles the whole LAN
as one client, and query logs, RPZ hits and ACLs all key on the node instead
of the client. Nothing fails, the numbers are just wrong — which is why this
is a render check and not a review rule.

``--allow NAME`` exempts a Service by name. Use it only where the source
address is not used for anything, and say why where the flag is passed.

Exit 0 when every VIP Service keeps the client address, 1 with one line per
offender.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Iterable
from typing import Any

import yaml

_VIP_ANNOTATION = "metallb.universe.tf/loadBalancerIPs"


class _EmptyRender(Exception):
    pass


def _offenders(docs: Iterable[dict[str, Any] | None], allow: set[str]) -> tuple[list[str], int]:
    """Offender lines, and how many VIP Services were checked."""
    out: list[str] = []
    seen = 0
    checked = 0
    for doc in docs:
        if isinstance(doc, dict):
            seen += 1
        if not isinstance(doc, dict) or doc.get("kind") != "Service":
            continue
        meta = doc.get("metadata") or {}
        spec = doc.get("spec") or {}
        if spec.get("type") != "LoadBalancer":
            continue
        if _VIP_ANNOTATION not in (meta.get("annotations") or {}):
            continue
        name = meta.get("name", "?")
        if name in allow:
            continue
        checked += 1
        policy = spec.get("externalTrafficPolicy")
        if policy != "Local":
            out.append(
                f"Service/{name}: MetalLB VIP with externalTrafficPolicy "
                f"{policy or 'unset (Cluster)'} — clients reach it SNATed"
            )
    # A failed render upstream of this check arrives as an empty stream, and
    # an empty stream has no offenders: refuse it rather than pass it.
    if not seen:
        raise _EmptyRender
    return out, checked


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("files", nargs="+", help="rendered manifests, or - for stdin")
    parser.add_argument("--allow", action="append", default=[], metavar="NAME")
    args = parser.parse_args(argv)

    offenders: list[str] = []
    checked = 0
    for path in args.files:
        try:
            if path == "-":
                found, n = _offenders(yaml.safe_load_all(sys.stdin), set(args.allow))
            else:
                with open(path, encoding="utf-8") as fh:
                    found, n = _offenders(yaml.safe_load_all(fh), set(args.allow))
        except _EmptyRender:
            offenders.append(f"{path}: no manifests — the render produced nothing to check")
            continue
        offenders += [f"{path}: {o}" for o in found]
        checked += n
    for line in offenders:
        print(line, file=sys.stderr)
    if not offenders:
        print(f"vip client address: {checked} MetalLB VIP Service(s) keep it")
    return 1 if offenders else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
