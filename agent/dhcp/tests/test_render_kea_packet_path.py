"""#980 — the two Kea packet-path settings, in both daemon blocks.

Both are rendered rather than left to Kea's defaults, and both defaults were
chosen from measurement against kea-dhcp4 3.0.3 (see
``DHCPServerGroup.kea_thread_pool_size`` for the numbers). What these tests
protect is the wiring: a value that is stored, shipped and then not rendered
is a silent no-op, which is the failure class #430 / #734 / #899 each found
one instance of.
"""

from __future__ import annotations

import pytest

from spatium_dhcp_agent.render_kea import render


def _bundle(**server_extra) -> dict:
    server = {"name": "dhcp1", "interfaces": ["eth0"]}
    server.update(server_extra)
    return {
        "server": server,
        "global_options": {"lease_time": 3600},
        "scopes": [
            {
                "subnet_cidr": "192.0.2.0/24",
                "lease_time": 3600,
                "pools": [
                    {
                        "start_ip": "192.0.2.100",
                        "end_ip": "192.0.2.200",
                        "pool_type": "dynamic",
                    }
                ],
                "options": {},
            },
            {
                "subnet_cidr": "2001:db8::/64",
                "address_family": "ipv6",
                "v6_address_mode": "stateful",
                "lease_time": 3600,
                "pools": [
                    {
                        "start_ip": "2001:db8::100",
                        "end_ip": "2001:db8::200",
                        "pool_type": "dynamic",
                    }
                ],
                "options": {},
            },
        ],
    }


# ── thread-pool-size ────────────────────────────────────────────────────────


@pytest.mark.parametrize("daemon", ["Dhcp4", "Dhcp6"])
def test_thread_pool_size_is_rendered_from_the_bundle(daemon):
    out = render(_bundle(kea_thread_pool_size=3))[daemon]
    assert out["multi-threading"]["thread-pool-size"] == 3


@pytest.mark.parametrize("daemon", ["Dhcp4", "Dhcp6"])
def test_multi_threading_stays_enabled_at_a_pool_of_one(daemon):
    """A pool of one is a resize, NOT ``enable-multi-threading: false``.

    With MT off, one thread must both receive and process; measured, that
    was 15,170 socket drops in a run where a pool of one had none. It also
    changes host-reservation lookup order and re-enables
    ``dhcp-queue-control``. Rendering it by accident would trade a
    throughput win for a semantics change nobody asked for.
    """
    out = render(_bundle(kea_thread_pool_size=1))[daemon]
    assert out["multi-threading"]["enable-multi-threading"] is True


@pytest.mark.parametrize("daemon", ["Dhcp4", "Dhcp6"])
def test_zero_is_passed_through_as_keas_auto_sizing(daemon):
    """0 is a real value — the operator opting back into Kea's own sizing —
    and must not be coalesced to the default it exists to escape."""
    out = render(_bundle(kea_thread_pool_size=0))[daemon]
    assert out["multi-threading"]["thread-pool-size"] == 0


@pytest.mark.parametrize("daemon", ["Dhcp4", "Dhcp6"])
def test_a_bundle_from_an_older_control_plane_gets_one_not_auto(daemon):
    """Absent means 1, not 0. "The field is missing" and "the operator asked
    for auto" must not render the same way: auto is the behaviour this
    setting exists to replace."""
    out = render(_bundle())[daemon]
    assert out["multi-threading"]["thread-pool-size"] == 1


# ── packet-queue-size (#1283) ───────────────────────────────────────────────


@pytest.mark.parametrize("daemon", ["Dhcp4", "Dhcp6"])
def test_packet_queue_size_is_rendered_not_left_at_keas_64(daemon):
    """Kea's multi-threading queue sits between the thread that reads the
    socket and the worker. Left unset it holds 64 packets, and when a burst
    outruns the worker Kea evicts the OLDEST queued packet to make room. No
    statistic counts that: ``pkt4-received`` is incremented by the worker
    that processes a packet, so an evicted one reaches no counter at all, and
    the only trace is a debug-level log line. Every product surface then
    shows a healthy server while clients retransmit, which is #1283.

    Rendered for both daemons (kea-dhcp6 runs the same queue) and for every
    bundle, including one from a control plane that predates the fix: this
    is the agent's own default, not a group setting."""
    out = render(_bundle())[daemon]
    assert out["multi-threading"]["packet-queue-size"] == 1024


@pytest.mark.parametrize("pool", [0, 1, 4])
def test_packet_queue_size_does_not_scale_with_the_pool(pool):
    """The queue is shared by the whole pool and its size is a bound on how
    long a request may wait (size / service rate). More workers drain it
    faster, so the same size is only ever safer; scaling it up with the pool
    would let a large pool queue requests past the client's first retransmit
    (4 s), which is the stale backlog #952 measured as a 34 s DORA."""
    out = render(_bundle(kea_thread_pool_size=pool))["Dhcp4"]
    assert out["multi-threading"]["packet-queue-size"] == 1024


# ── per-packet logging ──────────────────────────────────────────────────────


def _loggers(out, name):
    return [lg for lg in out["loggers"] if lg["name"] == name]


@pytest.mark.parametrize(
    ("daemon", "root"), [("Dhcp4", "kea-dhcp4"), ("Dhcp6", "kea-dhcp6")]
)
def test_packet_logging_on_by_default_leaves_the_child_alone(daemon, root):
    """Default must be byte-identical to what shipped before #980: no
    override at all, so the child inherits the parent's INFO."""
    out = render(_bundle())[daemon]
    assert _loggers(out, f"{root}.packets") == []
    assert _loggers(out, root)[0]["severity"] == "INFO"


@pytest.mark.parametrize(
    ("daemon", "root"), [("Dhcp4", "kea-dhcp4"), ("Dhcp6", "kea-dhcp6")]
)
def test_disabling_packet_logging_raises_only_that_child(daemon, root):
    out = render(_bundle(kea_packet_logging=False))[daemon]
    quiet = _loggers(out, f"{root}.packets")
    assert len(quiet) == 1
    assert quiet[0]["severity"] == "WARN"
    # The parent stays at INFO, or this would silence the lease lines the
    # Logs tab is built on.
    assert _loggers(out, root)[0]["severity"] == "INFO"


@pytest.mark.parametrize(
    ("daemon", "root"), [("Dhcp4", "kea-dhcp4"), ("Dhcp6", "kea-dhcp6")]
)
def test_the_daemon_child_logger_is_never_silenced(daemon, root):
    """``kea-dhcpN.dhcpN`` looks like the same kind of noise and is not.

    At INFO it carries ``DHCP4_OPEN_SOCKETS_FAILED`` — a real failure Kea
    logs at INFO — plus ``DHCP4_CONFIG_COMPLETE``, ``DHCP4_STARTED`` and
    ``DHCP4_MULTI_THREADING_INFO``, the last being the only line that
    reports whether the pool size above actually took effect. Verified
    against kea-dhcp4 3.0.3: silencing it loses all four.
    """
    out = render(_bundle(kea_packet_logging=False))[daemon]
    assert _loggers(out, f"{root}.{daemon.lower()}") == []


@pytest.mark.parametrize(
    ("daemon", "root"), [("Dhcp4", "kea-dhcp4"), ("Dhcp6", "kea-dhcp6")]
)
def test_the_quiet_child_declares_no_appenders_of_its_own(daemon, root):
    """The child must INHERIT the parent's appenders, not copy them.

    Verified against kea-dhcp4 3.0.3: a child configured with only a
    severity still reaches both stdout and the shipped file, so its WARNs
    and ERRORs are not lost. Copying the parent's ``output_options`` also
    works, but puts a second RollingFileAppender on the same path with its
    own rotation state — at 50 MB one renames the file while the other holds
    the old descriptor.
    """
    out = render(_bundle(kea_packet_logging=False))[daemon]
    quiet = _loggers(out, f"{root}.packets")[0]
    assert "output_options" not in quiet
    # Exactly one appender set per file, on the parent.
    parent = _loggers(out, root)[0]
    assert {o["output"] for o in parent["output_options"]} == {
        "stdout",
        f"/var/log/kea/{root}.log",
    }


# ── the HA hook's own thread pools (#980 review finding) ────────────────────


def _ha_bundle(**server_extra) -> dict:
    b = _bundle(**server_extra)
    b["failover"] = {
        "this_server_name": "a",
        "mode": "hot-standby",
        "peers": [
            {"name": "a", "url": "http://10.0.0.1:8000/", "role": "primary"},
            {"name": "b", "url": "http://10.0.0.2:8000/", "role": "standby"},
        ],
    }
    return b


def _ha_relationship(out):
    hook = [h for h in out["hooks-libraries"] if "ha.so" in h["library"]][0]
    return hook["parameters"]["high-availability"][0]


def test_ha_http_threads_do_not_follow_the_packet_pool():
    """Kea reads ``http-listener-threads: 0`` as "same as thread-pool-size",
    not as an independent auto-size — measured by counting OS threads: with
    the HA hook loaded, pool=1 gave 8 threads and pool=8 gave 29, three pools
    of N. Left alone, #980's pool of 1 would have serialised HA peer traffic
    as a side effect. They are pinned instead."""
    rel = _ha_relationship(render(_ha_bundle(kea_thread_pool_size=1))["Dhcp4"])
    mt = rel["multi-threading"]
    assert mt["http-listener-threads"] > 1
    assert mt["http-client-threads"] > 1
    assert mt["enable-multi-threading"] is True
    assert mt["http-dedicated-listener"] is True


def test_ha_http_threads_are_the_same_whatever_the_packet_pool():
    one = _ha_relationship(render(_ha_bundle(kea_thread_pool_size=1))["Dhcp4"])
    many = _ha_relationship(render(_ha_bundle(kea_thread_pool_size=16))["Dhcp4"])
    assert one["multi-threading"] == many["multi-threading"]
