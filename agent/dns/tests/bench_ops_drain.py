"""Local benchmark: how fast the DNS agent drains a record-op queue (#5025).

Not a test and not run in CI. It drives the real ``SyncLoop`` and the real
BIND9 driver's ``apply_record_op`` paths against

* a stand-in control plane that pages ops 5,000 at a time and, like the real
  one, sends the stored bundle body with every page (``--mode full``), or
  answers an ``X-Spatium-Ops-Only`` poll with the ops page alone
  (``--mode ops-only``); and
* a stand-in named on 127.0.0.1:53 (TCP) that answers SOA reads and accepts
  RFC 2136 UPDATEs, so each message costs a real loopback connection. It is a
  Python server, so absolute numbers are not named's; compare before / after,
  not this to production.

``--real-named`` starts a real ``named`` (on PATH, e.g. in the dns-bind9 image)
with one primary zone per ``--zones`` instead of the stand-in, and checks every
record the ops created answers.

It needs to bind port 53 (run it as root in a container)::

    docker run --rm -v "$PWD":/w -w /w python:3.12-slim sh -c \\
      'pip -q install -e . && python tests/bench_ops_drain.py --records 200000 \\
       --zones 2000 --ops 20000'

Run it from a checkout of the code under test: the same script runs on the
code before the change (it only touches what both have) and after.
"""

from __future__ import annotations

import argparse
import json
import multiprocessing as mp
import socketserver
import struct
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ETAG = "bench-etag"
STRUCTURAL = "bench-structural"
KEY = 'key "bench" { algorithm hmac-sha256; secret "c2VjcmV0c2VjcmV0c2VjcmV0"; };\n'


def zone_name(i: int) -> str:
    return f"z{i:05d}.bench."


def make_bundle(records: int, zones: int) -> dict:
    per = max(1, records // zones)
    return {
        "structural_etag": STRUCTURAL,
        "zones": [
            {
                "name": zone_name(z),
                "serial": 1,
                "type": "primary",
                "records": [
                    {"name": f"h{r}", "type": "A", "value": f"10.{z % 250}.{r // 250}.{r % 250}"}
                    for r in range(per)
                ],
            }
            for z in range(zones)
        ],
    }


def make_ops(n: int, zones: int) -> list[dict]:
    ops = []
    for k in range(n):
        z = (k // 25) % zones  # runs of 25 for one zone, as in the QA run's agent log
        value = f"10.200.{k // 250 % 250}.{k % 250}"
        ops.append(
            {
                "op_id": str(k),
                "zone_name": zone_name(z),
                "op": "create",
                "target_serial": 2 + k,
                "record": {
                    "name": f"n{k}",
                    "type": "A",
                    "value": value,
                    "ttl": 300,
                    "rrset": {"ttl": 300, "members": [{"value": value}]},
                },
            }
        )
    return ops


# ── stand-in control plane ───────────────────────────────────────────────


def serve_control_plane(
    port: int, body: bytes, ops: list[dict], page: int, mode: str, state
) -> None:
    sent = {"n": 0, "bytes": 0}

    class H(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *a):
            pass

        def do_POST(self):  # zone-state / heartbeat reports
            self.rfile.read(int(self.headers.get("Content-Length") or 0))
            out = b"{}"
            self.send_response(200)
            self.send_header("Content-Length", str(len(out)))
            self.end_headers()
            self.wfile.write(out)

        def do_GET(self):
            n = sent["n"]
            if n >= len(ops):
                state.value = 1
                self.send_response(304)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            chunk = ops[n : n + page]
            sent["n"] = n + len(chunk)
            remaining = len(ops) - sent["n"]
            head = (
                b'{"etag":"'
                + ETAG.encode()
                + b'","pending_record_ops":'
                + json.dumps(chunk, separators=(",", ":")).encode()
                + b',"pending_ops_remaining":'
                + str(remaining).encode()
                + b","
            )
            held = self.headers.get("If-None-Match") == ETAG
            if mode == "ops-only" and held and self.headers.get("X-Spatium-Ops-Only") == "1":
                out = head + b'"ops_only":true}'
            else:
                out = head + body[1:]
            sent["bytes"] += len(out)
            self.send_response(200)
            self.send_header("ETag", f'W/"{ETAG}"')
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(out)))
            self.end_headers()
            try:
                self.wfile.write(out)
            except OSError:
                pass  # an agent that read only the head closed the connection

    ThreadingHTTPServer.daemon_threads = True
    ThreadingHTTPServer(("127.0.0.1", port), H).serve_forever()


# ── stand-in named ───────────────────────────────────────────────────────


def serve_named(serials_per_zone: dict) -> None:
    import dns.flags
    import dns.message
    import dns.rcode
    import dns.rdata
    import dns.rrset
    import dns.tsigkeyring

    keyring = dns.tsigkeyring.from_text({"bench": "c2VjcmV0c2VjcmV0c2VjcmV0"})
    serials: dict[str, int] = {}

    class H(socketserver.BaseRequestHandler):
        def handle(self):
            sock = self.request
            while True:
                hdr = sock.recv(2)
                if len(hdr) < 2:
                    return
                (n,) = struct.unpack("!H", hdr)
                data = b""
                while len(data) < n:
                    part = sock.recv(n - len(data))
                    if not part:
                        return
                    data += part
                q = dns.message.from_wire(data, keyring=keyring, ignore_trailing=True)
                r = dns.message.make_response(q)
                if q.opcode() == 5:  # UPDATE
                    zone = q.zone[0].name.to_text()
                    for rr in q.update:
                        if rr.rdtype == 6 and rr.deleting is None:
                            serials[zone] = max(serials.get(zone, 1), rr[0].serial)
                    r.set_rcode(dns.rcode.NOERROR)
                else:
                    zone = q.question[0].name.to_text()
                    r.flags |= dns.flags.AA
                    soa = dns.rdata.from_text(
                        "IN",
                        "SOA",
                        f"ns1.{zone} h.{zone} {serials.get(zone, 1)} 3600 600 86400 300",
                    )
                    r.answer.append(dns.rrset.from_rdata(q.question[0].name, 300, soa))
                out = r.to_wire()
                sock.sendall(struct.pack("!H", len(out)) + out)

    class S(socketserver.ThreadingTCPServer):
        allow_reuse_address = True
        daemon_threads = True
        request_queue_size = 256

    S(("127.0.0.1", 53), H).serve_forever()


def start_real_named(state_dir: Path, zones: int):
    """Write a minimal named.conf with ``zones`` primary zones that take TSIG-signed
    updates, start named on 127.0.0.1:53 and wait until it answers."""
    import subprocess

    root = state_dir / "named"
    (root / "zones").mkdir(parents=True)
    conf = [
        f'options {{ directory "{root}"; listen-on port 53 {{ 127.0.0.1; }}; listen-on-v6 {{ none; }};',
        f'  recursion no; pid-file "{root}/named.pid"; session-keyfile "{root}/session.key"; }};',
        KEY.strip(),
    ]
    for z in range(zones):
        name = zone_name(z)
        (root / "zones" / f"{name}zone").write_text(
            f"$TTL 300\n@ IN SOA ns1.{name} h.{name} 1 3600 600 86400 300\n"
            f"@ IN NS ns1.{name}\nns1 IN A 192.0.2.1\n"
        )
        conf.append(
            f'zone "{name.rstrip(".")}" {{ type primary; file "zones/{name}zone"; '
            "allow-update { key bench; }; };"
        )
    (root / "named.conf").write_text("\n".join(conf) + "\n")
    with open(root / "named.log", "wb") as log_fh:
        proc = subprocess.Popen(
            ["named", "-g", "-c", str(root / "named.conf")],
            stdout=subprocess.DEVNULL,
            stderr=log_fh,
        )
    import dns.message
    import dns.query

    q = dns.message.make_query(zone_name(0), "SOA")
    for _ in range(120):
        try:
            if dns.query.tcp(q, "127.0.0.1", timeout=1).answer:
                return proc
        except Exception:  # noqa: BLE001 - not up yet
            time.sleep(0.5)
    raise SystemExit("named did not come up; see " + str(root / "named.log"))


def verify_served(ops: list[dict]) -> bool:
    """Ask the real named for every record the ops created."""
    import dns.message
    import dns.query

    bad = 0
    with_conn = 0
    for op in ops:
        name = f"{op['record']['name']}.{op['zone_name']}"
        r = dns.query.tcp(dns.message.make_query(name, "A"), "127.0.0.1", timeout=5)
        got = {rd.to_text() for rrs in r.answer for rd in rrs}
        with_conn += 1
        if op["record"]["value"] not in got:
            bad += 1
    print(f"served check: {with_conn - bad}/{with_conn} names answer", file=sys.stderr)
    return bad == 0


# ── the agent ────────────────────────────────────────────────────────────


class _Heartbeat:
    def __init__(self):
        from spatium_dns_agent.config_apply import ApplyStatus

        self.daemon_status = {}
        self.pending_acks = []
        self.failed_ops_count = 0
        self.config_apply = ApplyStatus()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--records", type=int, default=200_000)
    ap.add_argument("--zones", type=int, default=2_000)
    ap.add_argument("--ops", type=int, default=20_000)
    ap.add_argument("--page", type=int, default=5_000)
    ap.add_argument("--mode", choices=["full", "ops-only"], default="full")
    ap.add_argument("--port", type=int, default=18765)
    ap.add_argument(
        "--real-named",
        action="store_true",
        help="apply the ops to a real named (must be on PATH, run as root) instead of the stand-in",
    )
    args = ap.parse_args()

    from spatium_dns_agent.cache import ensure_layout, save_config
    from spatium_dns_agent.config import AgentConfig
    from spatium_dns_agent.drivers.bind9 import Bind9Driver
    from spatium_dns_agent.sync import SyncLoop

    state_dir = Path(tempfile.mkdtemp(prefix="bench-agent-"))
    ensure_layout(state_dir)
    bundle = make_bundle(args.records, args.zones)
    body = json.dumps(bundle, separators=(",", ":")).encode()
    print(
        f"bundle: {len(body) / 1e6:.1f} MB, {args.zones} zones, {args.records} records",
        file=sys.stderr,
    )
    (state_dir / "tsig").mkdir(exist_ok=True)
    (state_dir / "tsig" / "ddns.key").write_text(KEY)
    ops = make_ops(args.ops, args.zones)

    done = mp.Value("i", 0)
    cp = mp.Process(
        target=serve_control_plane,
        args=(args.port, body, ops, args.page, args.mode, done),
        daemon=True,
    )
    cp.start()
    if args.real_named:
        dns_srv = start_real_named(state_dir, args.zones)
    else:
        dns_srv = mp.Process(target=serve_named, args=({},), daemon=True)
        dns_srv.start()
    time.sleep(1.0)

    cfg = AgentConfig(
        control_plane_url=f"http://127.0.0.1:{args.port}",
        dns_agent_key="k",
        server_name="bench",
        driver="bind9",
        roles=["authoritative"],
        group_name="default",
        tls_ca_path=None,
        insecure_skip_tls_verify=True,
        state_dir=state_dir,
    )
    driver = Bind9Driver(state_dir=state_dir)
    # The sweep reads every primary zone the last render wrote (#2835).
    driver._rendered_has_views = False

    def apex(z: int) -> str:
        name = zone_name(z)
        state = {
            "name": name,
            "primary_ns": f"ns1.{name}",
            "admin_email": f"h.{name}",
            "ttl": 3600,
            "ns": [f"ns1.{name}"],
            "addressed": [],
            "signed": False,
        }
        return f"{name.rstrip('.')}\t{json.dumps(state, separators=(',', ':'))}"

    driver._apex_blob = ("\n" + "\n".join(apex(z) for z in range(args.zones)) + "\n").encode()
    # Built before the cache exists: a loop that finds one applies it with a
    # real named-checkconf, which this benchmark does not have.
    loop = SyncLoop(cfg, ["tok"], driver, _Heartbeat())
    save_config(state_dir, bundle, ETAG)
    loop._current_etag = ETAG
    loop._live_etag = ETAG
    loop._current_structural_etag = STRUCTURAL

    def watcher() -> None:
        while not done.value:
            time.sleep(0.2)
        loop._stop.set()

    threading.Thread(target=watcher, daemon=True).start()
    t0 = time.monotonic()
    loop.run()
    dt = time.monotonic() - t0
    acked = len(loop.heartbeat.pending_acks)
    ok = sum(1 for a in loop.heartbeat.pending_acks if a["result"] == "ok")
    errors = [a for a in loop.heartbeat.pending_acks if a["result"] != "ok"]
    if errors:
        print(f"first error: {errors[0].get('message')}", file=sys.stderr)
    # stderr: stdout carries the agent's own per-op log lines.
    print(
        f"mode={args.mode} ops={args.ops} acked={acked} ok={ok} seconds={dt:.1f} "
        f"ops/s={args.ops / dt:.1f}",
        file=sys.stderr,
    )
    served_ok = True
    if args.real_named:
        served_ok = verify_served(ops)
    cp.terminate()
    dns_srv.terminate()
    if args.real_named:
        dns_srv.wait()
    return 0 if ok == args.ops and served_ok else 1


if __name__ == "__main__":
    sys.exit(main())
