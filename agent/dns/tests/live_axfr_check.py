#!/usr/bin/env python3
"""Live TSIG-transfer check against a real ``named`` (#734).

Runs INSIDE the built bind9 agent image, where ``named``, ``python3``,
dnspython and the agent package all already exist. Renders a config with
the real :class:`Bind9Driver`, starts ``named`` on it, and asserts that a
zone transfer is permitted **only** when correctly TSIG-signed.

Why this exists as a standalone script rather than a pytest: the image
ships no test framework, and this has to run against the actual artifact
we publish — the agent renderer, the BIND version we pin, and the two
meeting on a real socket. A unit test can only prove we emit the string we
meant to emit; it cannot prove ``named`` reads that string the way we
believe it does.

Why it exists at all: before #734 the repo had **no automated AXFR
coverage anywhere**. ``grep -rl axfr .github/workflows`` returned nothing,
and the one test aimed at it —
``agent/dns/tests/test_acceptance.py::test_helm_chart_primary_secondary_axfr``
— was a permanent ``pytest.skip`` whose docstring claimed coverage lived
in ``agent-e2e.yml``. That workflow only ever ran ``dig version.bind CH
TXT``, a liveness smoke. So the skip stub was asserting a coverage that
did not exist, which is a large part of why #61's drift report could ship
broken against every agent-managed BIND9 and stay broken across two
releases.

Exits non-zero on the first failed expectation, so a CI step can simply
run it. Never skips: a missing prerequisite is a failure, because "the
check quietly didn't run" is the exact failure mode this replaces.
"""

from __future__ import annotations

import shutil
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

# Any valid base64; the peer only has to agree with us about the bytes.
_SECRET = "c2VjcmV0c2VjcmV0c2VjcmV0c2VjcmV0MDE="
_KEY = "spatium-live-check"
_OTHER_KEY = "operator-second-key"
# Deliberately a dotted, FQDN-shaped name — the form operators actually use
# for a DNSTSIGKey, and the one #920 was reported against.
_OPERATOR_KEY = "tsig-update.operator.example"
_ZONE = "live.example."
_PORT = 15353

_FAILURES: list[str] = []


def check(label: str, ok: bool, detail: str = "") -> None:
    print(f"  {'PASS' if ok else 'FAIL'}  {label}{f'  — {detail}' if detail else ''}")
    if not ok:
        _FAILURES.append(label)


def _bundle(tsig_keys: list[dict] | None = None) -> dict:
    return {
        "options": {
            "forwarders": [],
            "recursion_enabled": False,
            "allow_query": ["any"],
            "dnssec_validation": "no",
            # The stock default. Before #734 this denied everything AND the
            # key grant only existed on dynamic zones, so a static zone was
            # unreadable by anyone — which is the bug.
            "allow_transfer": ["none"],
        },
        "tsig_keys": tsig_keys
        if tsig_keys is not None
        else [
            {"name": _KEY, "secret": _SECRET, "algorithm": "hmac-sha256"},
            {"name": _OTHER_KEY, "secret": _SECRET, "algorithm": "hmac-sha256"},
        ],
        "zones": [
            {
                "name": _ZONE,
                "type": "primary",
                "ttl": 3600,
                "serial": 1,
                # Deliberately NOT a dynamic zone: the pre-#734 grant only
                # covered dynamic ones, so a static zone is the regression.
                "dynamic_update_enabled": False,
                "update_acl": [],
                "allow_transfer": None,
                "records": [
                    {"name": "www", "type": "A", "value": "192.0.2.1", "ttl": 300},
                    {"name": "mail", "type": "A", "value": "192.0.2.2", "ttl": 300},
                ],
            }
        ],
    }


def _wait_for_port(port: int, timeout: float = 20.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                return True
        except OSError:
            time.sleep(0.3)
    return False


def _wait_for_port_free(port: int, timeout: float = 10.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                time.sleep(0.2)
        except OSError:
            return


def _xfr(keyname: str | None, secret: str = _SECRET, algorithm: str = "hmac-sha256"):
    """Attempt an AXFR. Returns (ok, detail)."""
    import dns.name
    import dns.query
    import dns.tsig
    import dns.zone

    kwargs = {}
    if keyname is not None:
        kn = dns.name.from_text(keyname)
        algo = dns.name.from_text(algorithm)
        kwargs = {
            "keyring": {kn: dns.tsig.Key(kn, secret, algorithm=algo)},
            "keyname": kn,
            "keyalgorithm": algo,
        }
    try:
        z = dns.zone.from_xfr(
            dns.query.xfr(
                "127.0.0.1", dns.name.from_text(_ZONE), port=_PORT, timeout=10, **kwargs
            )
        )
        return True, f"{len(list(z.nodes))} nodes"
    except Exception as exc:  # noqa: BLE001 — every failure mode is a result here
        return False, type(exc).__name__


def _xfr_www(keyname: str | None, secret: str = _SECRET) -> tuple[bool, str]:
    """Attempt an AXFR and report WHICH copy came back: (ok, www's A value).

    Under split-horizon the same zone name holds different data per view,
    so "a transfer succeeded" proves nothing on its own — the value of the
    ``www`` record is what says which view answered.
    """
    import dns.name
    import dns.query
    import dns.rdatatype
    import dns.tsig
    import dns.zone

    kwargs = {}
    if keyname is not None:
        kn = dns.name.from_text(keyname)
        algo = dns.name.from_text("hmac-sha256")
        kwargs = {
            "keyring": {kn: dns.tsig.Key(kn, secret, algorithm=algo)},
            "keyname": kn,
            "keyalgorithm": algo,
        }
    try:
        z = dns.zone.from_xfr(
            dns.query.xfr(
                "127.0.0.1", dns.name.from_text(_ZONE), port=_PORT, timeout=10, **kwargs
            )
        )
    except Exception as exc:  # noqa: BLE001 — every failure mode is a result here
        return False, type(exc).__name__
    www = z.get_rdataset("www", dns.rdatatype.A)
    return True, ",".join(r.to_text() for r in www) if www else "<no www>"


# #920 — split-horizon. Every name below is a TEST-NET range, so no view ever
# matches 127.0.0.1 by address unless it says ``any``.
_VIEW_SECRETS = {
    "v-any": "dmlldy1hbnktdHJhbnNmZXIta2V5LXNlY3JldDAx",
    "v-a": "dmlldy1hLXRyYW5zZmVyLWtleS1zZWNyZXQwMDE=",
    "v-b": "dmlldy1iLXRyYW5zZmVyLWtleS1zZWNyZXQwMDE=",
    "v-corp": "dmlldy1jb3JwLXRyYW5zZmVyLWtleS1zZWNyZXQx",
}


def _view_key(view: str) -> str:
    return f"spatium_xfr_live_{view.replace('-', '_')}"


def _views_bundle(views: list[tuple[str, list[str], str]]) -> dict:
    """``views`` = [(name, match_clients, www address)], in precedence order.
    The same zone name lives in every view, holding a different ``www``."""
    base = _bundle()
    base["views"] = [
        {
            "id": None,
            "name": name,
            "match_clients": clients,
            "match_destinations": [],
            "recursion": False,
            "order": i,
            "allow_query": None,
            "allow_query_cache": None,
            "transfer_key": {
                "name": _view_key(name),
                "secret": _VIEW_SECRETS[name],
                "algorithm": "hmac-sha256",
            },
        }
        for i, (name, clients, _addr) in enumerate(views)
    ]
    template = base["zones"][0]
    base["zones"] = [
        {
            **template,
            "view_name": name,
            "records": [{"name": "www", "type": "A", "value": addr, "ttl": 300}],
        }
        for name, _clients, addr in views
    ]
    return base


def _render(bundle: dict) -> tuple[Path, Path]:
    """Render ``bundle`` into a fresh state dir. Returns (state, named.conf)."""
    from spatium_dns_agent.drivers.bind9 import Bind9Driver  # noqa: PLC0415

    state = Path(tempfile.mkdtemp(prefix="axfr-check-"))
    Bind9Driver(state_dir=state).render(bundle)
    # ``render`` stages into ``rendered.new`` while the zone-file paths it
    # writes into named.conf point at the promoted ``rendered`` directory —
    # the agent renames one to the other before starting the daemon. Do the
    # same, or named loads a config whose every zone file is missing and
    # then REFUSES transfers for not being authoritative, which looks
    # exactly like an ACL failure and is not one.
    rendered = state / "rendered"
    (state / "rendered.new").rename(rendered)
    conf = rendered / "named.conf"
    text = conf.read_text()

    # #920: the key include is derived from state_dir, so it already points at
    # the file render() just wrote. Assert that rather than rewriting it — a
    # hardcoded path here would send named to a DIFFERENT install's key file,
    # which passes named-checkconf and then fails every transfer BADKEY.
    expected_include = f'include "{state / "tsig" / "ddns.key"}";'
    check(
        "key include points at this render's own state dir",
        expected_include in text,
        expected_include,
    )

    # named needs a writable working directory it owns.
    conf.write_text(text.replace('directory "/var/cache/bind";', f'directory "{state}";'))
    return state, conf


def _run_case(label: str, bundle: dict, expectations) -> None:
    """Start named on ``bundle`` and run ``expectations`` against it."""
    print(f"\n=== {label} ===")
    state, conf = _render(bundle)
    text = conf.read_text()
    for line in text.splitlines():
        if "allow-transfer" in line:
            print(f"    {line.strip()[:120]}")

    proc = subprocess.Popen(  # noqa: S603 — fixed argv, no shell
        [shutil.which("named") or "named", "-c", str(conf), "-f", "-g", "-p", str(_PORT)],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    try:
        if not _wait_for_port(_PORT):
            proc.terminate()
            out = proc.communicate(timeout=10)[0]
            check(f"{label}: named listened on {_PORT}", False, out[-2000:])
            return
        expectations()
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
        # named holds the port briefly after exit; the next case rebinds it.
        _wait_for_port_free(_PORT)
        shutil.rmtree(state, ignore_errors=True)


def main() -> int:
    if not shutil.which("named"):
        print("FAIL: `named` not on PATH — this must run inside the bind9 agent image")
        return 1
    try:
        # Same ``from`` form ``_render`` uses — importing one module both
        # ways trips a code-quality check and reads as two dependencies.
        from spatium_dns_agent.drivers.bind9 import Bind9Driver  # noqa: F401,PLC0415
    except ImportError as exc:
        print(f"FAIL: agent package not importable ({exc})")
        return 1

    def group_key_expectations() -> None:
        ok, detail = _xfr(_KEY)
        check("signed with the group key returns the zone", ok, detail)

        ok, detail = _xfr(_OTHER_KEY)
        check("signed with a second granted key also works", ok, detail)

        # The regression itself. Pre-#734 this was the ONLY outcome, for
        # every zone, because the grant existed nowhere a static zone saw.
        ok, detail = _xfr(None)
        check("unsigned is REFUSED", not ok, detail)

        ok, detail = _xfr(_KEY, secret="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
        check("wrong secret is rejected", not ok, detail)

        ok, detail = _xfr(_KEY, algorithm="hmac-sha512")
        check("wrong algorithm is rejected", not ok, detail)

        ok, detail = _xfr("never-granted-key")
        check("a key the server never granted is rejected", not ok, detail)

    def operator_only_expectations() -> None:
        ok, detail = _xfr(_OPERATOR_KEY)
        check("operator-only: signed with the operator key returns the zone", ok, detail)

        ok, detail = _xfr(None)
        check("operator-only: unsigned is REFUSED", not ok, detail)

        # The distinction #920 turns on. A key named in named.conf answers
        # BADSIG for a wrong secret; a key named NOWHERE answers BADKEY. So
        # "wrong secret is rejected" passing here is what proves the operator
        # key was actually rendered, rather than the transfer failing for the
        # unrelated reason that named has never heard of it.
        ok, detail = _xfr(_OPERATOR_KEY, secret="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
        check("operator-only: wrong secret is rejected", not ok, detail)

    _run_case("group legacy key + operator key", _bundle(), group_key_expectations)

    # #920 — a group whose ONLY TSIG material is an operator DNSTSIGKey row.
    # This shape arises when a server is adopted into an existing group rather
    # than direct-registered, since only registration auto-mints the legacy
    # group key. ``tsig_keys[0]`` is then an operator key, which is the head
    # the control plane's ``resolve_group_transfer_key`` also picks.
    _run_case(
        "operator key only (no legacy group key)",
        _bundle([{"name": _OPERATOR_KEY, "secret": _SECRET, "algorithm": "hmac-sha256"}]),
        operator_only_expectations,
    )

    # #920 — a view scoped to the operator's own clients. Before its transfer
    # key existed, nothing admitted the control plane: the signed request
    # selected no view and named answered BADKEY for a key it had loaded.
    def scoped_view_expectations() -> None:
        ok, detail = _xfr_www(_view_key("v-corp"), _VIEW_SECRETS["v-corp"])
        check("scoped view: its transfer key reads the zone", ok and detail == "192.0.2.9", detail)

        ok, detail = _xfr_www(None)
        check("scoped view: unsigned is still REFUSED", not ok, detail)

        ok, detail = _xfr_www(_view_key("v-corp"), "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
        check("scoped view: a wrong secret on the view key is rejected", not ok, detail)

    _run_case(
        "split-horizon: a view that excludes the transfer source",
        _views_bundle([("v-corp", ["198.51.100.0/24"], "192.0.2.9")]),
        scoped_view_expectations,
    )

    # #920 — a broad view ahead of narrower ones. ``any`` matches 127.0.0.1,
    # so without the refusals every view key would be answered from v-any's
    # copy; with them each key reaches its own view.
    def broad_first_view_expectations() -> None:
        for view, addr in (("v-any", "192.0.2.1"), ("v-a", "192.0.2.2"), ("v-b", "192.0.2.3")):
            ok, detail = _xfr_www(_view_key(view), _VIEW_SECRETS[view])
            check(f"broad first view: {view}'s key reads {view}'s own copy", ok and detail == addr, detail)

        ok, detail = _xfr_www(None)
        check("broad first view: unsigned is still REFUSED", not ok, detail)

    _run_case(
        "split-horizon: a broad view ahead of narrower ones",
        _views_bundle(
            [
                ("v-any", ["any"], "192.0.2.1"),
                ("v-a", ["192.0.2.0/24"], "192.0.2.2"),
                ("v-b", ["203.0.113.0/24"], "192.0.2.3"),
            ]
        ),
        broad_first_view_expectations,
    )

    if _FAILURES:
        print(f"\n{len(_FAILURES)} expectation(s) failed: {', '.join(_FAILURES)}")
        return 1
    print("\nAll transfer expectations held.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
