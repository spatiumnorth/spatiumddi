#!/usr/bin/env python3
"""Every admission webhook in a render must fail OPEN (#1103).

The MetalLB chart validates its ``IPAddressPool`` / ``L2Advertisement`` through
a webhook served by the controller Deployment the same install creates. Helm 4
(klipper-helm, inside k3s) applies the ``ValidatingWebhookConfiguration`` before
those CRs, so they are admitted while the controller is not yet ready. At the
upstream default ``failurePolicy: Fail`` that is a hard rejection, and since
every retry of a k3s HelmChart uninstalls first, the controller that backs the
webhook is deleted again before the next attempt: setting a control-plane VIP
never converged.

``Ignore`` only changes what the apiserver does when it cannot REACH the
validator; once the controller is up the CRs are validated as before.

``helm lint`` and ``helm template`` both pass with ``Fail``: the failure needs a
live apiserver. So this checks the RENDERED policy, which a typo in the values
path (the setting silently not reaching the subchart) would also fail.

Run on the MetalLB render only. The BGP render also holds frr-k8s's webhook,
which stays at ``Fail`` deliberately: it validates ``FRRConfiguration``
objects the MetalLB speaker creates at RUNTIME and retries, not CRs in the
same Helm install, so it cannot wedge the install.

Usage: chart-webhooks-fail-open.py <rendered.yaml> [--require]
  --require   also fail when the render holds no webhook at all (the render
              is expected to include MetalLB's)
"""

from __future__ import annotations

import sys
from pathlib import Path

import yaml

KINDS = {"ValidatingWebhookConfiguration", "MutatingWebhookConfiguration"}


def main(argv: list[str]) -> int:
    args = [a for a in argv[1:] if not a.startswith("--")]
    flags = [a for a in argv[1:] if a.startswith("--")]
    require = "--require" in flags
    # An unknown flag is refused rather than ignored: a typo'd ``--require``
    # would otherwise silently turn "no webhook rendered" into a pass.
    unknown = [f for f in flags if f != "--require"]
    if unknown or len(args) != 1:
        if unknown:
            print(f"unknown flag(s): {' '.join(unknown)}", file=sys.stderr)
        print(__doc__, file=sys.stderr)
        return 2
    path = Path(args[0])
    docs = [d for d in yaml.safe_load_all(path.read_text(encoding="utf-8")) if d]

    seen = 0
    bad: list[str] = []
    for doc in docs:
        if doc.get("kind") not in KINDS:
            continue
        name = (doc.get("metadata") or {}).get("name", "?")
        for hook in doc.get("webhooks") or []:
            seen += 1
            # The apiserver's default when the field is absent is Fail.
            policy = hook.get("failurePolicy", "Fail")
            if policy != "Ignore":
                bad.append(f"{name}/{hook.get('name', '?')}: failurePolicy {policy}")

    if require and not seen:
        print(f"{path.name}: expected admission webhooks in this render, found none")
        return 1
    if bad:
        print(f"{path.name}: webhooks that fail closed during their own install (#1103):")
        for line in bad:
            print(f"  {line}")
        return 1
    print(f"   ok: {seen} webhook(s) fail open")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
