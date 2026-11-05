#!/usr/bin/env python3
"""Live check: a blocklist does not switch DNSSEC validation off (#3563).

Runs INSIDE the built bind9 agent image, where ``named``, ``dig``,
``python3``, dnspython and the agent package already exist. Two ``named``
processes on loopback:

* an **authoritative** one serving ``example.com.``, signed here with
  dnspython (the image ships no ``dnssec-signzone``), with one record whose
  signature is deliberately broken after signing;
* a **resolver** rendered by the real :class:`Bind9Driver` from a bundle that
  carries a blocklist, ``dnssec_validation: auto``, a static trust anchor for
  ``example.com.`` and the authoritative one as its only forwarder.

Before #3563 the agent forced ``dnssec-validation no`` whenever a group had
any blocklist, on the claim that BIND would otherwise SERVFAIL a DO=1 query
for a blocked signed name even with ``break-dnssec yes``. This proves the
opposite against the BIND we ship, and that validation keeps working:

* the blocked signed name is rewritten for DO=1 and for DO=0 clients;
* an unblocked signed name validates (AD bit);
* a bogus-signed name answers SERVFAIL;
* a SafeSearch-style ``redirect`` entry (#878) — an RPZ CNAME rewrite of a
  signed name onto another signed name — answers the redirect target, with
  the target's address, for DO=1 and DO=0 clients.

A negative control re-runs the resolver with ``break-dnssec no``, where a
DO=1 query for the blocked name must get the real (signed) answer — which
proves the DO=1 queries above really did ask about a validated signed name.

Exits non-zero on the first failed expectation; never skips.
"""

from __future__ import annotations

import base64
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

_RESOLVER_PORT = 15353
_AUTH_PORT = 15354
_ZONE = "example.com."
_BLOCKED = "blocked.example.com."
_GOOD = "good.example.com."
_BOGUS = "bogus.example.com."
_BOGUS_SIGNED_ADDR = "192.0.2.66"
_BOGUS_SERVED_ADDR = "192.0.2.99"
# SafeSearch shape (#878): a redirect of one signed name onto another.
_SEARCH = "search.example.com."
_SEARCH_REAL_ADDR = "192.0.2.30"
_SAFE = "safe.example.com."
_SAFE_ADDR = "192.0.2.40"

_FAILURES: list[str] = []


def check(label: str, ok: bool, detail: str = "") -> None:
    print(f"  {'PASS' if ok else 'FAIL'}  {label}{f'  — {detail}' if detail else ''}")
    if not ok:
        _FAILURES.append(label)


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


def _signed_zone(workdir: Path) -> tuple[Path, str]:
    """Sign ``example.com.`` and break one signature. Returns (file, KSK b64)."""
    import dns.dnssec
    import dns.rdatatype
    import dns.zone
    from cryptography.hazmat.primitives.asymmetric import ec

    alg = dns.dnssec.Algorithm.ECDSAP256SHA256
    ksk = ec.generate_private_key(ec.SECP256R1())
    zsk = ec.generate_private_key(ec.SECP256R1())
    ksk_key = dns.dnssec.make_dnskey(ksk.public_key(), alg, flags=257)
    zsk_key = dns.dnssec.make_dnskey(zsk.public_key(), alg, flags=256)

    text = f"""\
$TTL 300
@        SOA ns1 hostmaster 1 3600 600 86400 300
@        NS  ns1
ns1      A   127.0.0.1
good     A   192.0.2.20
blocked  A   192.0.2.10
bogus    A   {_BOGUS_SIGNED_ADDR}
search   A   {_SEARCH_REAL_ADDR}
safe     A   {_SAFE_ADDR}
"""
    zone = dns.zone.from_text(text, origin=_ZONE, relativize=False)
    with zone.writer() as txn:
        dns.dnssec.sign_zone(
            zone,
            txn=txn,
            keys=[(ksk, ksk_key), (zsk, zsk_key)],
            add_dnskey=True,
            dnskey_ttl=300,
            lifetime=86400,
        )
    signed = zone.to_text(relativize=False)
    # Change the bogus A rdata AFTER signing, leaving its RRSIG in place: the
    # signature no longer covers what is served, so a validator must refuse it.
    tampered = signed.replace(f"A {_BOGUS_SIGNED_ADDR}", f"A {_BOGUS_SERVED_ADDR}")
    assert tampered != signed, "bogus A record not found in the signed zone text"
    path = workdir / "example.com.db"
    path.write_text(tampered)
    return path, base64.b64encode(ksk_key.key).decode()


def _start_auth(workdir: Path, zone_file: Path) -> subprocess.Popen:
    conf = workdir / "auth.conf"
    conf.write_text(f"""\
options {{
    directory "{workdir}";
    pid-file "{workdir}/auth.pid";
    listen-on port {_AUTH_PORT} {{ 127.0.0.1; }};
    listen-on-v6 {{ none; }};
    recursion no;
    dnssec-validation no;
}};
controls {{ }};
zone "{_ZONE.rstrip('.')}" {{ type primary; file "{zone_file}"; }};
""")
    return subprocess.Popen(
        [shutil.which("named") or "named", "-c", str(conf), "-f", "-g"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )


_VIEW = {
    "id": "v1",
    "name": "internal",
    "match_clients": ["any"],
    "match_destinations": [],
    "recursion": True,
    "order": 0,
}


def _bundle(ksk_b64: str, views: bool = False) -> dict:
    return {
        "views": [dict(_VIEW)] if views else [],
        "options": {
            "recursion_enabled": True,
            "allow_query": ["any"],
            "dnssec_validation": "auto",
            "forwarders": [f"127.0.0.1@{_AUTH_PORT}"],
            "forward_policy": "only",
            "trust_anchors": [
                {
                    "zone_name": _ZONE,
                    "algorithm": 13,
                    "public_key": ksk_b64,
                    "is_initial_key": False,
                }
            ],
        },
        "zones": [],
        "tsig_keys": [],
        "blocklists": [
            {
                "rpz_zone_name": "spatium-blocklist.rpz.",
                "entries": [
                    {
                        "domain": _BLOCKED.rstrip("."),
                        "action": "block",
                        "block_mode": "nxdomain",
                    },
                    {
                        "domain": _SEARCH.rstrip("."),
                        "action": "redirect",
                        "target": _SAFE.rstrip("."),
                    },
                ],
                "exceptions": [],
                "view_name": None,
            }
        ],
    }


def _render_resolver(ksk_b64: str, views: bool) -> tuple[Path, Path]:
    from spatium_dns_agent.drivers.bind9 import Bind9Driver

    state = Path(tempfile.mkdtemp(prefix="rpz-dnssec-check-"))
    Bind9Driver(state_dir=state).render(_bundle(ksk_b64, views))
    # ``render`` stages into ``rendered.new``; the paths in named.conf point
    # at the promoted ``rendered`` directory, as the agent's swap leaves it.
    rendered = state / "rendered"
    (state / "rendered.new").rename(rendered)
    conf = rendered / "named.conf"
    text = conf.read_text()
    text = text.replace('directory "/var/cache/bind";', f'directory "{state}";')
    text = text.replace('key-directory "/var/cache/bind/keys";', f'key-directory "{state}";')
    # The rendered statistics channel binds a fixed port; not needed here.
    text = text.replace("inet 127.0.0.1 port 8053", "inet 127.0.0.1 port 18053")
    conf.write_text(text)
    return state, conf


def _query(name: str, dnssec: bool):
    import dns.message
    import dns.query

    q = dns.message.make_query(name, "A", want_dnssec=dnssec)
    return dns.query.udp(q, "127.0.0.1", port=_RESOLVER_PORT, timeout=10)


def _dig(name: str, dnssec: bool) -> None:
    flag = "+dnssec" if dnssec else "+nodnssec"
    out = subprocess.run(
        [
            shutil.which("dig") or "dig",
            "@127.0.0.1",
            "-p",
            str(_RESOLVER_PORT),
            name,
            "A",
            flag,
            "+noall",
            "+comments",
            "+answer",
            "+tries=1",
            "+time=10",
        ],
        check=False,
        capture_output=True,
        text=True,
    ).stdout
    print(f"    $ dig @127.0.0.1 -p {_RESOLVER_PORT} {name} A {flag}")
    for line in out.splitlines():
        if line.strip() and not line.startswith(";; Got answer"):
            print(f"      {line}")


def _summary(resp) -> tuple[str, bool, list[str]]:
    import dns.flags
    import dns.rcode
    import dns.rdatatype

    addrs = [r.to_text() for rrset in resp.answer if rrset.rdtype == dns.rdatatype.A for r in rrset]
    return dns.rcode.to_text(resp.rcode()), bool(resp.flags & dns.flags.AD), addrs


def _cname_targets(resp) -> list[str]:
    import dns.rdatatype

    return [
        r.target.to_text()
        for rrset in resp.answer
        if rrset.rdtype == dns.rdatatype.CNAME
        for r in rrset
    ]


def _run_resolver(
    label: str, ksk_b64: str, break_dnssec: bool, expectations, views: bool = False
) -> None:
    print(f"\n=== {label} ===")
    state, conf = _render_resolver(ksk_b64, views)
    text = conf.read_text()
    if not break_dnssec:
        text = text.replace("break-dnssec yes", "break-dnssec no")
        conf.write_text(text)
    for line in text.splitlines():
        if "dnssec-validation" in line or "response-policy" in line:
            print(f"    {line.strip()}")

    proc = subprocess.Popen(
        [
            shutil.which("named") or "named",
            "-c",
            str(conf),
            "-f",
            "-g",
            "-p",
            str(_RESOLVER_PORT),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    try:
        if not _wait_for_port(_RESOLVER_PORT):
            proc.terminate()
            out = proc.communicate(timeout=10)[0]
            check(f"{label}: resolver listened on {_RESOLVER_PORT}", False, out[-2000:])
            return
        expectations(text)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
        _wait_for_port_free(_RESOLVER_PORT)
        shutil.rmtree(state, ignore_errors=True)


def main() -> int:
    for tool in ("named", "dig"):
        if not shutil.which(tool):
            print(f"FAIL: `{tool}` not on PATH — this must run inside the bind9 agent image")
            return 1
    try:
        from spatium_dns_agent.drivers.bind9 import Bind9Driver  # noqa: F401
    except ImportError as exc:
        print(f"FAIL: agent package not importable ({exc})")
        return 1

    workdir = Path(tempfile.mkdtemp(prefix="rpz-dnssec-auth-"))
    zone_file, ksk_b64 = _signed_zone(workdir)
    auth = _start_auth(workdir, zone_file)
    try:
        if not _wait_for_port(_AUTH_PORT):
            auth.terminate()
            out = auth.communicate(timeout=10)[0]
            print(f"FAIL: authoritative named did not start\n{out[-2000:]}")
            return 1

        def filtered_expectations(conf_text: str) -> None:
            check(
                "named.conf keeps the group's dnssec-validation (auto) with a blocklist",
                "dnssec-validation auto;" in conf_text,
            )
            for do in (True, False):
                tag = "DO=1" if do else "DO=0"
                _dig(_BLOCKED, do)
                rcode, _ad, addrs = _summary(_query(_BLOCKED, do))
                check(
                    f"{tag}: blocked signed name is rewritten (NXDOMAIN)",
                    rcode == "NXDOMAIN" and not addrs,
                    f"{rcode} {addrs}",
                )
            for do in (True, False):
                tag = "DO=1" if do else "DO=0"
                _dig(_GOOD, do)
                rcode, ad, addrs = _summary(_query(_GOOD, do))
                check(
                    f"{tag}: unblocked signed name resolves",
                    rcode == "NOERROR" and addrs == ["192.0.2.20"],
                    f"{rcode} {addrs}",
                )
                if do:
                    check(f"{tag}: unblocked signed name validates (AD)", ad, f"AD={ad}")
            for do in (True, False):
                tag = "DO=1" if do else "DO=0"
                _dig(_SEARCH, do)
                resp = _query(_SEARCH, do)
                rcode, _ad, addrs = _summary(resp)
                cnames = _cname_targets(resp)
                check(
                    f"{tag}: SafeSearch-style redirect of a signed name answers the target",
                    rcode == "NOERROR" and cnames == [_SAFE] and addrs == [_SAFE_ADDR],
                    f"{rcode} CNAME={cnames} {addrs}",
                )
            for do in (True, False):
                tag = "DO=1" if do else "DO=0"
                _dig(_BOGUS, do)
                rcode, _ad, addrs = _summary(_query(_BOGUS, do))
                check(
                    f"{tag}: bogus-signed name is SERVFAIL",
                    rcode == "SERVFAIL",
                    f"{rcode} {addrs}",
                )

        _run_resolver(
            "blocklist + dnssec-validation auto + break-dnssec yes",
            ksk_b64,
            True,
            filtered_expectations,
        )
        # Split-horizon: the response-policy moves into the view, and the
        # view inherits ``dnssec-validation`` from options.
        _run_resolver(
            "view-scoped blocklist + dnssec-validation auto + break-dnssec yes",
            ksk_b64,
            True,
            filtered_expectations,
            views=True,
        )

        def control_expectations(_conf_text: str) -> None:
            _dig(_BLOCKED, True)
            rcode, ad, addrs = _summary(_query(_BLOCKED, True))
            check(
                "control (break-dnssec no): DO=1 blocked name gets the real, "
                "validated answer — so the DO=1 checks above hit a signed name",
                rcode == "NOERROR" and addrs == ["192.0.2.10"] and ad,
                f"{rcode} {addrs} AD={ad}",
            )
            _dig(_SEARCH, True)
            rcode, ad, addrs = _summary(_query(_SEARCH, True))
            check(
                "control (break-dnssec no): DO=1 redirected name gets the real, "
                "validated answer — so the DO=1 redirect check above hit a signed name",
                rcode == "NOERROR" and addrs == [_SEARCH_REAL_ADDR] and ad,
                f"{rcode} {addrs} AD={ad}",
            )

        _run_resolver("negative control: break-dnssec no", ksk_b64, False, control_expectations)
    finally:
        auth.terminate()
        try:
            auth.wait(timeout=10)
        except subprocess.TimeoutExpired:
            auth.kill()
        shutil.rmtree(workdir, ignore_errors=True)

    if _FAILURES:
        print(f"\n{len(_FAILURES)} expectation(s) failed: {', '.join(_FAILURES)}")
        return 1
    print("\nAll RPZ + DNSSEC expectations held.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
