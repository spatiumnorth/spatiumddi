"""Seed a running SpatiumDDI instance with realistic demo data for screenshots.

Usage (with the compose stack running):
    python3 scripts/seed_demo.py http://localhost:8000 admin admin

Creates a representative slice of every first-class entity that's
shipped to date so screenshots look populated and the AI Copilot's
dynamic context block has real numbers to summarise. Sections:

* DNS — group + forward zone + reverse zone + records
* DHCP — server group, scope on one subnet, dynamic pool
* ASN — operator's local AS + a couple of upstream peers
* VRF — default + guest + iot
* IP space — Corporate (with VRF + ASN), Guest, IoT
* IP blocks + subnets, with VLAN / gateway
* IP addresses — random allocation across most subnets
* Network devices — SNMP-stubbed (is_active=False so beat doesn't poll)
* VLANs — legacy router/VLAN entries (the screenshot UI still uses these)
* Domains — corp.example.com (matches the DNS zone) + example.com
* Custom fields — one IP-level + one subnet-level
* IPAM templates — one block + one subnet template
* IPAM NAT mappings — 1to1 / pat / hide examples
* Multicast — PIM domain, multicast-kind subnet, group + ports + membership
* Subnet plan — a draft planner workspace (not applied)
* Network modeling — customers / sites / providers / circuits / services /
  applications / SD-WAN overlays + overlay-sites + routing policies
* DNS sub-resources — view, ACL, TSIG key, DNSSEC policy, GSLB pool,
  blocklist + entry + exception, catalog-template zone
* DHCP sub-resources — client class, static reservation, MAC blocklist,
  option template, PXE profile, phone profile
* Governance — custom role, sample group + non-admin user, time-bound
  grant, scoped API token, custom conformity policy, webhook subscription
* Alert rules — utilization, server-unreachable, domain-expiring
* AI prompts — three shared triage prompts (issue #90 Phase 2)

Several of those sections sit behind feature modules that do not ship
enabled (#1069), so the run starts by turning them on — see
``DEMO_MODULES``. Without that the gated routers answer 404 and the demo
data for them simply never appears.

Every section is idempotent — the script swallows 409 from already-
existing rows, and PATCHes spaces / blocks where the FK targets need
to converge on a re-run after new entities exist. A handful of
endpoints have no uniqueness constraint (time-bound grants, API
tokens, conformity policies, webhook subscriptions); those sections
list-then-skip on a stable key so a re-run doesn't pile up duplicates.

Out of scope: AI providers (secrets), audit-forward targets
(per-deployment endpoints), and every read-only-pull integration
target (Kubernetes / Docker / Proxmox / Tailscale / UniFi / OPNsense /
Cloud) — those need real creds / live external systems. The webhook
subscription seeded here points at a deliberately non-resolving host
and ships disabled so the worker never attempts delivery.
"""

from __future__ import annotations

import random
import sys

import httpx


def login(base: str, user: str, pw: str) -> str:
    r = httpx.post(f"{base}/api/v1/auth/login", json={"username": user, "password": pw})
    r.raise_for_status()
    return r.json()["access_token"]


class Api:
    """Thin idempotent JSON-over-HTTP client.

    409 (already exists) is swallowed silently — that's what makes the
    seed re-runnable. Every other 4xx / 5xx is logged but doesn't
    abort the run, since later sections often don't depend on earlier
    failures (e.g. domain creation doesn't need DHCP to succeed).
    """

    def __init__(self, base: str, token: str):
        self.c = httpx.Client(
            base_url=base, headers={"Authorization": f"Bearer {token}"}, timeout=30.0
        )

    def call(self, method: str, path: str, **kwargs):
        try:
            r = self.c.request(method, path, **kwargs)
        except httpx.HTTPError as e:
            print(f"  ! {method} {path} transport error: {e}")
            return None
        if r.status_code == 409:
            return None
        if r.status_code >= 400:
            print(f"  ! {method} {path} -> {r.status_code}: {r.text[:200]}")
            return None
        return r.json() if r.content else None


def find(items, key, val):
    if not items:
        return None
    return next((i for i in items if i.get(key) == val), None)


# ── Section: DNS ──────────────────────────────────────────────────────────


def seed_dns(a: Api) -> tuple[str | None, str | None, str | None]:
    """Returns ``(group_id, forward_zone_id, reverse_zone_id)`` so the
    space + domain rows can pin them.
    """
    print("Creating DNS group + zones + records…")
    a.call(
        "POST",
        "/api/v1/dns/groups",
        json={
            "name": "default",
            "description": "Main DNS cluster",
            "group_type": "internal",
            "is_recursive": True,
        },
    )
    groups = a.call("GET", "/api/v1/dns/groups") or []
    g = find(groups, "name", "default")
    if not g:
        return None, None, None
    gid = g["id"]

    # Forward zone — the space defaults to this and the AI copilot
    # uses it as a worked example for "list my DNS records" queries.
    a.call(
        "POST",
        f"/api/v1/dns/groups/{gid}/zones",
        json={"name": "corp.example.com", "zone_type": "primary", "kind": "forward"},
    )
    # Reverse zone — DDNS / PTR auto-population queries traverse this.
    a.call(
        "POST",
        f"/api/v1/dns/groups/{gid}/zones",
        json={"name": "10.in-addr.arpa", "zone_type": "primary", "kind": "reverse"},
    )
    zones = a.call("GET", f"/api/v1/dns/groups/{gid}/zones") or []
    fz = find(zones, "name", "corp.example.com")
    rz = find(zones, "name", "10.in-addr.arpa")
    fz_id = fz["id"] if fz else None
    rz_id = rz["id"] if rz else None

    if fz_id:
        for rec in [
            {"name": "www", "record_type": "A", "value": "10.10.10.20", "ttl": 3600},
            {"name": "mail", "record_type": "A", "value": "10.10.10.25", "ttl": 3600},
            {
                "name": "@",
                "record_type": "MX",
                "value": "10 mail.corp.example.com.",
                "ttl": 3600,
                "priority": 10,
            },
            {
                "name": "_sip._tcp",
                "record_type": "SRV",
                "value": "10 10 5060 voip.corp.example.com.",
                "ttl": 3600,
            },
            {
                "name": "office",
                "record_type": "TXT",
                "value": '"v=spf1 ip4:10.1.0.0/16 -all"',
                "ttl": 3600,
            },
        ]:
            a.call("POST", f"/api/v1/dns/groups/{gid}/zones/{fz_id}/records", json=rec)

    return gid, fz_id, rz_id


# ── Section: DHCP ─────────────────────────────────────────────────────────


def seed_dhcp_group(a: Api) -> str | None:
    print("Creating DHCP server group…")
    a.call(
        "POST",
        "/api/v1/dhcp/server-groups",
        json={
            "name": "default",
            "description": "Default DHCP group",
            "mode": "hot-standby",
        },
    )
    groups = a.call("GET", "/api/v1/dhcp/server-groups") or []
    g = find(groups, "name", "default")
    return g["id"] if g else None


def seed_dhcp_scope(a: Api, group_id: str | None, subnets: list[dict]) -> str | None:
    """Wire a scope on the Servers subnet so the DHCP page isn't empty.

    The subnet has gateway + DDNS already inherited from the space; the
    scope just configures the lease window + a small dynamic pool.
    Returns the scope id so the DHCP sub-resources section can attach
    statics / phone-profile scope links to it.
    """
    if not group_id or not subnets:
        return None
    target = find(subnets, "name", "Servers")
    if not target:
        return None
    print("Creating DHCP scope + pool on Servers subnet…")
    scope = a.call(
        "POST",
        f"/api/v1/dhcp/subnets/{target['id']}/dhcp-scopes",
        json={
            "group_id": group_id,
            "name": "Servers DHCP",
            "lease_time": 86400,
            "enabled": True,
            "ddns_enabled": True,
        },
    )
    scope_id = scope["id"] if scope and scope.get("id") else None
    if scope_id is None:
        # Re-run path: the scope already exists (409 swallowed above). Look
        # it up so downstream sections still get an id to attach to.
        scopes = a.call("GET", f"/api/v1/dhcp/server-groups/{group_id}/scopes") or []
        existing = find(scopes, "name", "Servers DHCP")
        scope_id = existing["id"] if existing else None
    if scope_id:
        # Small dynamic pool so screenshots show "▼ start / ▲ end" rows
        # in the IPAM table.
        a.call(
            "POST",
            f"/api/v1/dhcp/scopes/{scope_id}/pools",
            json={
                "name": "Default pool",
                "start_ip": "10.10.10.100",
                "end_ip": "10.10.10.149",
                "pool_type": "dynamic",
            },
        )
    return scope_id


# ── Section: ASNs + VRFs ──────────────────────────────────────────────────


def seed_asns(a: Api) -> dict[str, str]:
    """Returns ``{name: id}`` for the seeded ASNs."""
    print("Creating ASNs…")
    rows = [
        {
            "number": 64512,
            "name": "Corporate",
            "description": "Operator's private AS (RFC 6996 16-bit private range)",
        },
        {
            "number": 13335,
            "name": "Cloudflare",
            "description": "Upstream peer — public",
            "holder_org": "Cloudflare, Inc.",
        },
        {
            "number": 174,
            "name": "Cogent",
            "description": "Transit provider — public",
            "holder_org": "Cogent Communications",
        },
    ]
    for body in rows:
        a.call("POST", "/api/v1/asns", json=body)
    listed = a.call("GET", "/api/v1/asns") or {}
    items = listed.get("items", listed) if isinstance(listed, dict) else listed
    return {row["name"]: row["id"] for row in items if row.get("name")}


def seed_peerings(a: Api, asns: dict[str, str]):
    if "Corporate" not in asns:
        return
    print("Creating BGP peerings…")
    local = asns["Corporate"]
    for peer_name, kind in (
        ("Cloudflare", "peer"),
        ("Cogent", "provider"),
    ):
        peer = asns.get(peer_name)
        if not peer:
            continue
        a.call(
            "POST",
            "/api/v1/asns/peerings",
            json={
                "local_asn_id": local,
                "peer_asn_id": peer,
                "relationship_type": kind,
                "description": f"{peer_name} {kind}",
            },
        )


def seed_vrfs(a: Api, asns: dict[str, str]) -> dict[str, str]:
    print("Creating VRFs…")
    corp = asns.get("Corporate")
    rows = [
        {
            "name": "default",
            "description": "Underlay VRF for the corporate network",
            "asn_id": corp,
            "route_distinguisher": "64512:1" if corp else None,
            "import_targets": ["64512:1"] if corp else [],
            "export_targets": ["64512:1"] if corp else [],
        },
        {
            "name": "guest",
            "description": "Guest WiFi — internet-only, no internal access",
            "asn_id": corp,
            "route_distinguisher": "64512:100" if corp else None,
        },
        {
            "name": "iot",
            "description": "IoT segment — restricted east-west",
            "asn_id": corp,
            "route_distinguisher": "64512:200" if corp else None,
        },
    ]
    for body in rows:
        # Strip None values so the API's strict-RD validator doesn't
        # 422 when ASN seeding failed and we passed RD=None.
        clean = {k: v for k, v in body.items() if v is not None}
        a.call("POST", "/api/v1/vrfs", json=clean)
    listed = a.call("GET", "/api/v1/vrfs") or []
    return {row["name"]: row["id"] for row in listed if row.get("name")}


# ── Section: IPAM ─────────────────────────────────────────────────────────


def seed_spaces_blocks_subnets(
    a: Api,
    *,
    dns_group_id: str | None,
    dns_zone_id: str | None,
    dhcp_group_id: str | None,
    vrfs: dict[str, str],
    asns: dict[str, str],
) -> tuple[str | None, list[dict]]:
    """Returns ``(corporate_space_id, list_of_seeded_subnets)``."""
    print("Creating IP space…")
    space_payload: dict = {
        "name": "Corporate",
        "description": "Primary office network",
    }
    if dns_group_id:
        space_payload["dns_group_ids"] = [dns_group_id]
    if dns_zone_id:
        space_payload["dns_zone_id"] = dns_zone_id
    if dhcp_group_id:
        space_payload["dhcp_server_group_id"] = dhcp_group_id
    if vrfs.get("default"):
        space_payload["vrf_id"] = vrfs["default"]
    if asns.get("Corporate"):
        space_payload["asn_id"] = asns["Corporate"]
    a.call("POST", "/api/v1/ipam/spaces", json=space_payload)

    spaces = a.call("GET", "/api/v1/ipam/spaces") or []
    corp = find(spaces, "name", "Corporate")
    if not corp:
        print("! could not create/find Corporate space")
        return None, []
    space_id = corp["id"]

    # On re-run, converge stale FK pointers if previous-run entities now
    # exist. Without this, a fresh seed against an already-seeded DB
    # leaves dangling values.
    patch: dict = {}
    if dns_group_id and corp.get("dns_group_ids") != [dns_group_id]:
        patch["dns_group_ids"] = [dns_group_id]
    if dns_zone_id and corp.get("dns_zone_id") != dns_zone_id:
        patch["dns_zone_id"] = dns_zone_id
    if dhcp_group_id and corp.get("dhcp_server_group_id") != dhcp_group_id:
        patch["dhcp_server_group_id"] = dhcp_group_id
    if vrfs.get("default") and corp.get("vrf_id") != vrfs["default"]:
        patch["vrf_id"] = vrfs["default"]
    if asns.get("Corporate") and corp.get("asn_id") != asns["Corporate"]:
        patch["asn_id"] = asns["Corporate"]
    if patch:
        a.call("PUT", f"/api/v1/ipam/spaces/{space_id}", json=patch)

    print("Creating blocks…")
    a.call(
        "POST",
        "/api/v1/ipam/blocks",
        json={
            "space_id": space_id,
            "name": "HQ 10.0.0.0/8",
            "network": "10.0.0.0/8",
            "description": "Headquarters aggregate",
        },
    )
    a.call(
        "POST",
        "/api/v1/ipam/blocks",
        json={
            "space_id": space_id,
            "name": "DMZ 192.168.0.0/16",
            "network": "192.168.0.0/16",
            "description": "DMZ and lab",
        },
    )
    blocks = a.call("GET", f"/api/v1/ipam/blocks?space_id={space_id}") or []
    hq = find(blocks, "name", "HQ 10.0.0.0/8")
    dmz = find(blocks, "name", "DMZ 192.168.0.0/16")
    if not hq or not dmz:
        print("! block creation failed")
        return space_id, []

    print("Creating subnets…")
    subnet_specs = [
        (hq["id"], "Office-LAN", "10.1.0.0/24", "Staff workstations", 10),
        (hq["id"], "Voice-VLAN", "10.1.1.0/24", "VoIP phones", 11),
        (hq["id"], "Servers", "10.10.10.0/24", "Production servers", 20),
        (hq["id"], "Wireless-Staff", "10.20.0.0/22", "Corporate WiFi", 30),
        (dmz["id"], "DMZ-Public", "192.168.1.0/24", "Public-facing hosts", 100),
        (dmz["id"], "Lab", "192.168.99.0/24", "Test/lab network", 200),
    ]
    for block_id, name, net, desc, vlan_id in subnet_specs:
        a.call(
            "POST",
            "/api/v1/ipam/subnets",
            json={
                "space_id": space_id,
                "block_id": block_id,
                "name": name,
                "network": net,
                "description": desc,
                "gateway": net.rsplit(".", 1)[0] + ".1",
                "vlan_id": vlan_id,
            },
        )

    all_subnets = a.call("GET", "/api/v1/ipam/subnets") or []
    seeded_names = {name for _, name, _, _, _ in subnet_specs}
    subnets = [s for s in all_subnets if s["name"] in seeded_names]
    return space_id, subnets


def seed_addresses(a: Api, subnets: list[dict]):
    print(f"Allocating IPs into {len(subnets)} subnet(s)…")
    hostname_pool = [
        "web01",
        "web02",
        "db-primary",
        "db-replica",
        "app-api",
        "app-worker",
        "mail",
        "git",
        "jenkins",
        "grafana",
        "prometheus",
        "vault",
        "consul",
        "nfs01",
        "backup",
        "printer-lobby",
        "printer-2f",
        "ap-floor1",
        "ap-floor2",
        "jdoe-laptop",
        "asmith-desktop",
        "mlee-laptop",
        "kvm-1",
        "kvm-2",
    ]
    random.seed(42)
    for subnet in subnets:
        # Wireless / Lab stay sparse on purpose so utilization charts
        # show variance in the dashboard heatmap.
        if "Wireless" in subnet["name"] or "Lab" in subnet["name"]:
            continue
        for _ in range(random.randint(3, 8)):
            hn = random.choice(hostname_pool) + f"-{random.randint(100, 999)}"
            mac = ":".join(f"{random.randint(0, 255):02x}" for _ in range(6))
            a.call(
                "POST",
                f"/api/v1/ipam/subnets/{subnet['id']}/next",
                json={
                    "hostname": hn,
                    "mac_address": mac,
                    "description": "",
                    "status": "allocated",
                },
            )


# ── Section: Network devices + VLANs ──────────────────────────────────────


def seed_network_devices(a: Api, space_id: str | None):
    """SNMP-stubbed devices.

    ``is_active=False`` so the SNMP-poll beat task doesn't actually
    probe these hostnames (which would 404 on a bare seed). Operators
    flip them active once they've pointed each row at a real switch.
    """
    if not space_id:
        return
    print("Creating SNMP-stubbed network devices…")
    rows = [
        {
            "name": "core-sw1",
            "hostname": "core-sw1.corp.example.com",
            "ip_address": "10.1.0.2",
            "device_type": "switch",
            "description": "HQ core switch — Cisco Catalyst 9300",
            "snmp_version": "v2c",
            "community": "public-readonly",
            "ip_space_id": space_id,
            "is_active": False,
        },
        {
            "name": "dmz-sw1",
            "hostname": "dmz-sw1.corp.example.com",
            "ip_address": "192.168.1.2",
            "device_type": "switch",
            "description": "DMZ switch — Arista 7050SX",
            "snmp_version": "v2c",
            "community": "public-readonly",
            "ip_space_id": space_id,
            "is_active": False,
        },
        {
            "name": "edge-fw1",
            "hostname": "edge-fw1.corp.example.com",
            "ip_address": "10.0.0.254",
            "device_type": "firewall",
            "description": "Internet edge firewall",
            "snmp_version": "v2c",
            "community": "public-readonly",
            "ip_space_id": space_id,
            "is_active": False,
        },
    ]
    for body in rows:
        a.call("POST", "/api/v1/network-devices", json=body)


def seed_legacy_vlans(a: Api):
    """The legacy VLANs page (under Network → VLANs) still uses the
    router-keyed model. Seed two routers + a handful of VLANs so the
    page isn't empty for demos.
    """
    print("Creating legacy router + VLAN entries…")
    a.call(
        "POST",
        "/api/v1/vlans/routers",
        json={
            "name": "core-sw1",
            "description": "HQ core switch",
            "location": "MDF rack A",
            "management_ip": "10.1.0.1",
            "vendor": "Cisco",
            "model": "Catalyst 9300",
        },
    )
    a.call(
        "POST",
        "/api/v1/vlans/routers",
        json={
            "name": "dmz-sw1",
            "description": "DMZ switch",
            "location": "Server room B",
            "management_ip": "192.168.1.1",
            "vendor": "Arista",
            "model": "7050SX",
        },
    )
    routers = a.call("GET", "/api/v1/vlans/routers") or []
    core = find(routers, "name", "core-sw1")
    dmz_sw = find(routers, "name", "dmz-sw1")
    if core:
        for vid, name in [
            (10, "Office"),
            (11, "Voice"),
            (20, "Servers"),
            (30, "WiFi-Staff"),
        ]:
            a.call(
                "POST",
                f"/api/v1/vlans/routers/{core['id']}/vlans",
                json={"vlan_id": vid, "name": name, "description": ""},
            )
    if dmz_sw:
        for vid, name in [(100, "DMZ-Public"), (200, "Lab")]:
            a.call(
                "POST",
                f"/api/v1/vlans/routers/{dmz_sw['id']}/vlans",
                json={"vlan_id": vid, "name": name, "description": ""},
            )


# ── Section: Domains ──────────────────────────────────────────────────────


def seed_domains(a: Api):
    """RDAP refresh + alert-rule expiry trigger off these.

    Keep the list small and realistic — we don't want the seed to
    flood the operator's Domain page with dozens of rows.
    """
    print("Creating domains…")
    rows = [
        {
            "name": "corp.example.com",
            "expected_nameservers": ["ns1.corp.example.com", "ns2.corp.example.com"],
        },
        {
            "name": "example.com",
            "expected_nameservers": ["a.iana-servers.net", "b.iana-servers.net"],
        },
    ]
    for body in rows:
        a.call("POST", "/api/v1/domains", json=body)


# ── Section: Custom fields + IPAM templates ───────────────────────────────


def seed_custom_fields(a: Api):
    """One field per resource type so the per-resource admin pages
    have a worked example.
    """
    print("Creating custom fields…")
    rows = [
        {
            "resource_type": "ip_address",
            "name": "owner",
            "label": "Owner",
            "field_type": "text",
            "is_required": False,
            "is_searchable": True,
            "default_value": "",
            "display_order": 0,
            "description": "Operator team or person responsible for this IP",
            "options": None,
        },
        {
            "resource_type": "subnet",
            "name": "environment",
            "label": "Environment",
            "field_type": "select",
            "is_required": False,
            "is_searchable": True,
            "default_value": "production",
            "display_order": 0,
            "description": "Subnet environment classification",
            "options": ["production", "staging", "development", "lab"],
        },
    ]
    for body in rows:
        a.call("POST", "/api/v1/custom-fields", json=body)


def seed_ipam_templates(a: Api, dns_group_id: str | None, dhcp_group_id: str | None):
    """Two templates — one block-shaped (with child layout) + one
    subnet-shaped — so the IPAM Templates admin page has something
    operators can click "apply".
    """
    print("Creating IPAM templates…")
    block_template: dict = {
        "name": "Standard /24 block",
        "description": "Three /27 subnets carved out — staff / phones / servers",
        "applies_to": "block",
        "tags": {},
        "custom_fields": {},
        "ddns_enabled": True,
        "ddns_hostname_policy": "leave_unchanged",
        "child_layout": {
            "children": [
                {"prefix": 27, "name_template": "Staff-{n}", "description": ""},
                {"prefix": 27, "name_template": "Phones-{n}", "description": ""},
                {"prefix": 27, "name_template": "Servers-{n}", "description": ""},
            ]
        },
    }
    subnet_template: dict = {
        "name": "Standard subnet",
        "description": "Default DNS / DHCP / DDNS for new subnets",
        "applies_to": "subnet",
        "tags": {},
        "custom_fields": {},
        "ddns_enabled": True,
        "ddns_hostname_policy": "leave_unchanged",
    }
    if dns_group_id:
        block_template["dns_group_id"] = dns_group_id
        subnet_template["dns_group_id"] = dns_group_id
    if dhcp_group_id:
        block_template["dhcp_group_id"] = dhcp_group_id
        subnet_template["dhcp_group_id"] = dhcp_group_id
    a.call("POST", "/api/v1/ipam/templates", json=block_template)
    a.call("POST", "/api/v1/ipam/templates", json=subnet_template)


# ── Section: Alerts ───────────────────────────────────────────────────────


def seed_alert_rules(a: Api):
    """Three rules covering the three families of subjects the
    evaluator currently understands. Disabled by default — operators
    flip them on once they've configured an audit-forward target.
    """
    print("Creating alert rules…")
    rows = [
        {
            "name": "Subnet 90% utilised",
            "description": "Fires when any tracked subnet hits ≥ 90% utilisation.",
            "rule_type": "subnet_utilization",
            "threshold_percent": 90,
            "severity": "warning",
            "enabled": False,
            "notify_syslog": False,
            "notify_webhook": True,
            "notify_smtp": False,
        },
        {
            "name": "DNS server unreachable",
            "description": "Fires when a DNS server's health check fails.",
            "rule_type": "server_unreachable",
            "server_type": "dns",
            "severity": "critical",
            "enabled": False,
            "notify_syslog": True,
            "notify_webhook": True,
            "notify_smtp": False,
        },
        {
            "name": "Domain expiring within 30 days",
            "description": "Fires when a tracked domain is < 30 d from expiry.",
            "rule_type": "domain_expiring",
            "threshold_days": 30,
            "severity": "warning",
            "enabled": False,
            "notify_syslog": False,
            "notify_webhook": True,
            "notify_smtp": True,
        },
    ]
    for body in rows:
        a.call("POST", "/api/v1/alerts/rules", json=body)


# ── Section: AI prompts (issue #90 Phase 2) ───────────────────────────────


def seed_ai_prompts(a: Api):
    """A few shared prompts the operator's Copilot drawer will surface
    in its 'Prompts ▾' picker.
    """
    print("Creating shared AI prompts…")
    rows = [
        {
            "name": "Daily IPAM triage",
            "description": "Walk every subnet ≥ 80% utilised and list resize candidates.",
            "prompt_text": (
                "Walk through every subnet whose utilisation is at or above 80%. "
                "For each, list the current size, current allocated count, and "
                "suggest whether resize, split, or new-block is the right move. "
                "Group by IPSpace."
            ),
            "is_shared": True,
        },
        {
            "name": "Find static / DHCP collisions",
            "description": "List statically-assigned IPs that fall inside an active DHCP scope.",
            "prompt_text": (
                "Find every IP address with status='allocated' or 'reserved' that "
                "falls inside an active DHCP scope's dynamic pool range. Group by "
                "subnet. For each collision, name the static row, the scope, and "
                "the pool range it conflicts with."
            ),
            "is_shared": True,
        },
        {
            "name": "Audit log triage",
            "description": "Summarise the last hour of audit events grouped by user.",
            "prompt_text": (
                "Summarise the last hour of audit log events. Group by user. "
                "Highlight anything that looks unusual (off-hours activity, "
                "cross-resource bursts, repeated failures). Keep it under 200 words."
            ),
            "is_shared": True,
        },
    ]
    for body in rows:
        a.call("POST", "/api/v1/ai/prompts", json=body)


# ── Section: IPAM NAT mappings ────────────────────────────────────────────


def seed_nat_mappings(a: Api, subnets: list[dict]):
    """Three NAT mappings — one of each kind (1to1 / pat / hide).

    internal_ip / external_ip are plain strings; the handler auto-resolves
    them to IPAM rows when they happen to match a seeded address. Each
    mapping uses a distinct external_ip so the external-slot conflict
    guard (409) never fires. The hide mapping needs a real Subnet id, so
    it pins to the seeded Office-LAN subnet when present.
    """
    print("Creating NAT mappings…")
    a.call(
        "POST",
        "/api/v1/ipam/nat-mappings",
        json={
            "name": "web01 public NAT",
            "kind": "1to1",
            "internal_ip": "10.10.10.20",
            "external_ip": "203.0.113.10",
            "protocol": "any",
            "device_label": "edge-fw1",
            "description": "1:1 NAT for the web server",
        },
    )
    a.call(
        "POST",
        "/api/v1/ipam/nat-mappings",
        json={
            "name": "app-api 443->8443 PAT",
            "kind": "pat",
            "internal_ip": "10.10.10.30",
            "internal_port_start": 8443,
            "external_ip": "203.0.113.11",
            "external_port_start": 443,
            "protocol": "tcp",
            "description": "Port-forward HTTPS to app-api",
        },
    )
    office_lan = find(subnets, "name", "Office-LAN")
    if office_lan:
        a.call(
            "POST",
            "/api/v1/ipam/nat-mappings",
            json={
                "name": "Office-LAN hide NAT",
                "kind": "hide",
                "internal_subnet_id": office_lan["id"],
                "external_ip": "203.0.113.1",
                "protocol": "any",
                "description": "Masquerade staff LAN behind the edge public IP",
            },
        )
    else:
        print("  · skipping hide-NAT (no Office-LAN subnet to pin internal_subnet_id)")


# ── Section: Multicast ────────────────────────────────────────────────────


def seed_multicast(
    a: Api,
    space_id: str | None,
    subnets: list[dict],
):
    """PIM domain + multicast-kind subnet + group + ports + membership.

    The whole /multicast surface is feature-module gated (network.multicast,
    default-enabled) so a non-200 is tolerated. Subnet.kind is auto-detected
    from the CIDR — a 224.0.0.0/4 network stores as kind='multicast', no
    operator-settable field. The group create auto-creates its own enclosing
    block, but we also seed a dedicated multicast subnet so the IPAM tree
    renders the range like a real subnet.
    """
    if not space_id:
        print("  · skipping multicast (no Corporate space id)")
        return
    print("Creating multicast domain + subnet + group…")

    # PIM domain. pim_mode='ssm' needs no rendezvous point, so it's the
    # zero-FK safe choice (sparse/bidir would 422 without an RP).
    a.call(
        "POST",
        "/api/v1/multicast/domains",
        json={
            "name": "HQ PIM-SSM",
            "description": "Headquarters source-specific multicast domain",
            "pim_mode": "ssm",
            "ssm_range": "232.0.0.0/8",
            "notes": "",
        },
    )

    # Multicast-range block (encloses 239.0.0.0/8) so the multicast subnet
    # has a parent. _assert_no_overlap runs on both, so the ranges are
    # picked to not collide with the unicast blocks/subnets.
    a.call(
        "POST",
        "/api/v1/ipam/blocks",
        json={
            "space_id": space_id,
            "name": "Multicast 239.0.0.0/8",
            "network": "239.0.0.0/8",
            "description": "Administratively-scoped multicast (RFC 2365)",
        },
    )
    blocks = a.call("GET", f"/api/v1/ipam/blocks?space_id={space_id}") or []
    mcast_block = find(blocks, "name", "Multicast 239.0.0.0/8")
    if mcast_block:
        a.call(
            "POST",
            "/api/v1/ipam/subnets",
            json={
                "space_id": space_id,
                "block_id": mcast_block["id"],
                "network": "239.10.0.0/24",
                "name": "Video multicast",
                "description": "Administratively-scoped multicast (RFC 2365)",
            },
        )

    # Multicast group. Needs only space_id + address (in 224.0.0.0/4); the
    # handler ensures an enclosing block exists on its own.
    group = a.call(
        "POST",
        "/api/v1/multicast/groups",
        json={
            "space_id": space_id,
            "address": "239.10.0.10",
            "name": "IPTV-Channel-1",
            "description": "Set-top-box video stream",
            "application": "IPTV",
            "rtp_payload_type": 33,
        },
    )
    group_id = group["id"] if group and group.get("id") else None
    if group_id is None:
        # Re-run: resolve the group by address so ports / memberships still
        # have a parent to attach to.
        listed = (
            a.call(
                "GET",
                f"/api/v1/multicast/groups?space_id={space_id}&search=239.10.0.10",
            )
            or {}
        )
        items = listed.get("items", []) if isinstance(listed, dict) else []
        existing = find(items, "address", "239.10.0.10")
        group_id = existing["id"] if existing else None

    if not group_id:
        print(
            "  · multicast group unavailable (module disabled?); skipping ports + membership"
        )
        return

    # RTP + RTCP port pair on the group.
    a.call(
        "POST",
        f"/api/v1/multicast/groups/{group_id}/ports",
        json={
            "port_start": 5004,
            "port_end": 5005,
            "transport": "rtp",
            "notes": "RTP + RTCP pair",
        },
    )

    # Membership needs a real IPAM address id. Pull one from the Servers
    # subnet (the seeder already allocated several IPs there).
    servers = find(subnets, "name", "Servers")
    addr_id = None
    if servers:
        addresses = (
            a.call("GET", f"/api/v1/ipam/subnets/{servers['id']}/addresses") or []
        )
        allocated = next(
            (
                ip
                for ip in addresses
                if ip.get("status") == "allocated" and ip.get("id")
            ),
            None,
        )
        if allocated is None and addresses:
            allocated = next((ip for ip in addresses if ip.get("id")), None)
        addr_id = allocated["id"] if allocated else None
    if addr_id:
        a.call(
            "POST",
            f"/api/v1/multicast/groups/{group_id}/memberships",
            json={
                "ip_address_id": addr_id,
                "role": "producer",
                "seen_via": "manual",
                "notes": "Encoder feeding the stream",
            },
        )
    else:
        print("  · skipping multicast membership (no allocated IP in Servers subnet)")


# ── Section: Subnet plan ──────────────────────────────────────────────────


def seed_subnet_plan(a: Api, space_id: str | None):
    """A draft planner workspace. The tree is a draft only — it does NOT
    materialise blocks/subnets until /apply (which the seeder never calls),
    so it's safe demo data with no side effects.
    """
    if not space_id:
        print("  · skipping subnet plan (no Corporate space id)")
        return
    print("Creating subnet plan (draft)…")
    a.call(
        "POST",
        "/api/v1/ipam/plans",
        json={
            "name": "Branch office /24 carve",
            "description": "Draft layout for a new branch — 2x /26",
            "space_id": space_id,
            "tree": {
                "id": "root",
                "network": "172.16.0.0/24",
                "name": "Branch aggregate",
                "kind": "block",
                "children": [
                    {
                        "id": "n1",
                        "network": "172.16.0.0/26",
                        "name": "Staff",
                        "kind": "subnet",
                        "children": [],
                    },
                    {
                        "id": "n2",
                        "network": "172.16.0.64/26",
                        "name": "Phones",
                        "kind": "subnet",
                        "children": [],
                    },
                ],
            },
        },
    )


# ── Section: Network modeling (ownership + circuits + services + overlays) ──


def seed_customers(a: Api) -> dict[str, str]:
    print("Creating customers…")
    rows = [
        {
            "name": "Acme Corp",
            "account_number": "ACME-001",
            "contact_email": "netops@acme.example",
            "status": "active",
        },
        {
            "name": "Globex Retail",
            "account_number": "GLBX-002",
            "contact_email": "it@globex.example",
            "status": "active",
        },
    ]
    for body in rows:
        a.call("POST", "/api/v1/customers", json=body)
    listed = a.call("GET", "/api/v1/customers") or {}
    items = listed.get("items", []) if isinstance(listed, dict) else listed
    return {row["name"]: row["id"] for row in items if row.get("name")}


def seed_sites(a: Api) -> dict[str, str]:
    print("Creating sites…")
    rows = [
        {
            "name": "HQ Datacenter",
            "code": "HQ-DC1",
            "kind": "datacenter",
            "region": "us-east",
        },
        {
            "name": "Branch — Austin",
            "code": "BR-AUS",
            "kind": "branch",
            "region": "us-central",
        },
        {
            "name": "Branch — Denver",
            "code": "BR-DEN",
            "kind": "branch",
            "region": "us-west",
        },
    ]
    for body in rows:
        a.call("POST", "/api/v1/sites", json=body)
    listed = a.call("GET", "/api/v1/sites") or {}
    items = listed.get("items", []) if isinstance(listed, dict) else listed
    return {row["name"]: row["id"] for row in items if row.get("name")}


def seed_providers(a: Api, asns: dict[str, str]) -> dict[str, str]:
    print("Creating providers…")
    rows: list[dict] = [
        {
            "name": "Cogent Communications",
            "kind": "transit",
            "account_number": "CGT-99",
            "contact_email": "noc@cogent.example",
        },
        {
            "name": "Lumen Fiber",
            "kind": "carrier",
            "account_number": "LMN-44",
            "contact_email": "noc@lumen.example",
        },
    ]
    # Wire the Cogent provider to the seeded Cogent ASN when available.
    if asns.get("Cogent"):
        rows[0]["default_asn_id"] = asns["Cogent"]
    for body in rows:
        a.call("POST", "/api/v1/providers", json=body)
    listed = a.call("GET", "/api/v1/providers") or {}
    items = listed.get("items", []) if isinstance(listed, dict) else listed
    return {row["name"]: row["id"] for row in items if row.get("name")}


def seed_circuits(
    a: Api,
    providers: dict[str, str],
    customers: dict[str, str],
    sites: dict[str, str],
    subnets: list[dict],
) -> dict[str, str]:
    """WAN circuits. provider_id is REQUIRED (RESTRICT); a/z-end sites are
    wired to seeded sites so the topology + by-site views populate.
    """
    provider_id = providers.get("Cogent Communications")
    if not provider_id:
        print("  · skipping circuits (no provider id)")
        return {}
    print("Creating WAN circuits…")
    hq = sites.get("HQ Datacenter")
    aus = sites.get("Branch — Austin")
    den = sites.get("Branch — Denver")
    acme = customers.get("Acme Corp")
    servers = find(subnets, "name", "Servers")
    a_end_subnet = servers["id"] if servers else None

    specs = [
        {
            "name": "HQ-Austin MPLS",
            "ckt_id": "CKT-10042",
            "transport_class": "mpls",
            "bandwidth_mbps_down": 100,
            "bandwidth_mbps_up": 100,
            "a_end_site_id": hq,
            "z_end_site_id": aus,
        },
        {
            "name": "HQ-Denver MPLS",
            "ckt_id": "CKT-10043",
            "transport_class": "mpls",
            "bandwidth_mbps_down": 100,
            "bandwidth_mbps_up": 100,
            "a_end_site_id": hq,
            "z_end_site_id": den,
        },
        {
            "name": "HQ Internet DIA",
            "ckt_id": "CKT-20001",
            "transport_class": "internet_broadband",
            "bandwidth_mbps_down": 1000,
            "bandwidth_mbps_up": 1000,
            "a_end_site_id": hq,
        },
    ]
    for spec in specs:
        body: dict = {
            "provider_id": provider_id,
            "status": "active",
            "currency": "USD",
        }
        body.update({k: v for k, v in spec.items() if v is not None})
        if acme:
            body["customer_id"] = acme
        if a_end_subnet:
            body["a_end_subnet_id"] = a_end_subnet
        a.call("POST", "/api/v1/circuits", json=body)

    listed = a.call("GET", "/api/v1/circuits") or {}
    items = listed.get("items", []) if isinstance(listed, dict) else listed
    return {row["name"]: row["id"] for row in items if row.get("name")}


def seed_applications(a: Api):
    """One custom application-category row. Builtins (office365, zoom,
    microsoft_teams, …) are seeded at startup and already satisfy
    routing-policy matches; this is demo flavour.
    """
    print("Creating custom application category…")
    a.call(
        "POST",
        "/api/v1/applications",
        json={
            "name": "Acme ERP",  # normalised server-side to acme_erp
            "description": "Acme internal ERP",
            "category": "saas",
            "default_dscp": 18,
        },
    )


def seed_services(
    a: Api,
    customers: dict[str, str],
    vrfs: dict[str, str],
    sites: dict[str, str],
    circuits: dict[str, str],
    subnets: list[dict],
):
    """A custom-kind service with a few resources attached.

    kind='custom' lets us attach several resource kinds freely (an
    mpls_l3vpn enforces at-most-one-VRF). Each attach is idempotent —
    re-attaching the same (kind, id) just updates the role.
    """
    customer_id = customers.get("Acme Corp")
    if not customer_id:
        print("  · skipping network service (no customer id)")
        return
    print("Creating network service + resource attaches…")
    svc = a.call(
        "POST",
        "/api/v1/services",
        json={
            "name": "Acme Managed WAN",
            "kind": "custom",
            "customer_id": customer_id,
            "status": "active",
            "currency": "USD",
        },
    )
    service_id = svc["id"] if svc and svc.get("id") else None
    if service_id is None:
        listed = a.call("GET", "/api/v1/services") or {}
        items = listed.get("items", []) if isinstance(listed, dict) else listed
        existing = find(items, "name", "Acme Managed WAN")
        service_id = existing["id"] if existing else None
    if not service_id:
        print("  · service unavailable; skipping resource attaches")
        return

    attaches: list[dict] = []
    if vrfs.get("default"):
        attaches.append(
            {"resource_kind": "vrf", "resource_id": vrfs["default"], "role": "core"}
        )
    for site_name in ("HQ Datacenter", "Branch — Austin"):
        if sites.get(site_name):
            attaches.append(
                {
                    "resource_kind": "site",
                    "resource_id": sites[site_name],
                    "role": "edge",
                }
            )
    if circuits.get("HQ-Austin MPLS"):
        attaches.append(
            {
                "resource_kind": "circuit",
                "resource_id": circuits["HQ-Austin MPLS"],
                "role": "edge",
            }
        )
    servers = find(subnets, "name", "Servers")
    if servers:
        attaches.append(
            {"resource_kind": "subnet", "resource_id": servers["id"], "role": "lan"}
        )
    for body in attaches:
        a.call("POST", f"/api/v1/services/{service_id}/resources", json=body)


def seed_overlays(
    a: Api,
    customers: dict[str, str],
    sites: dict[str, str],
    circuits: dict[str, str],
):
    """SD-WAN overlay + hub/spoke site membership + a routing policy.

    To get topology EDGES, the hub + spokes share one MPLS circuit in
    their preferred_circuits. The routing policy uses match_kind='dscp'
    + mark_dscp so it needs no application-catalog or circuit FK.
    """
    print("Creating SD-WAN overlay + sites + policy…")
    body: dict = {
        "name": "Acme SD-WAN",
        "kind": "sdwan",
        "vendor": "cisco_meraki",
        "default_path_strategy": "active_backup",
        "status": "active",
    }
    if customers.get("Acme Corp"):
        body["customer_id"] = customers["Acme Corp"]
    ov = a.call("POST", "/api/v1/overlays", json=body)
    overlay_id = ov["id"] if ov and ov.get("id") else None
    if overlay_id is None:
        listed = a.call("GET", "/api/v1/overlays") or {}
        items = listed.get("items", []) if isinstance(listed, dict) else listed
        existing = find(items, "name", "Acme SD-WAN")
        overlay_id = existing["id"] if existing else None
    if not overlay_id:
        print("  · overlay unavailable; skipping sites + policy")
        return

    hub_circuit = circuits.get("HQ-Austin MPLS")
    shared = [hub_circuit] if hub_circuit else []
    members = [
        ("HQ Datacenter", "hub"),
        ("Branch — Austin", "spoke"),
        ("Branch — Denver", "spoke"),
    ]
    for site_name, role in members:
        site_id = sites.get(site_name)
        if not site_id:
            continue
        site_body: dict = {"site_id": site_id, "role": role}
        if shared:
            site_body["preferred_circuits"] = shared
        a.call("POST", f"/api/v1/overlays/{overlay_id}/sites", json=site_body)

    a.call(
        "POST",
        f"/api/v1/overlays/{overlay_id}/policies",
        json={
            "name": "Mark EF for voice",
            "priority": 100,
            "match_kind": "dscp",
            "match_value": "46",
            "action": "mark_dscp",
            "action_target": "46",
            "enabled": True,
        },
    )


# ── Section: DNS sub-resources ────────────────────────────────────────────


def seed_dns_subresources(
    a: Api,
    dns_group_id: str | None,
    dns_fwd_zone_id: str | None,
):
    """View, ACL, TSIG key, DNSSEC policy, GSLB pool, blocklist tree, and a
    catalog-template zone. All persist without a live agent.
    """
    print("Creating DNS sub-resources…")

    # DNSSEC policy is global (not group-scoped) — seed it regardless.
    a.call(
        "POST",
        "/api/v1/dns/dnssec-policies",
        json={
            "name": "ecdsa-default",
            "description": "ECDSA P-256, 90d ZSK rollover",
            "algorithm": "ecdsap256sha256",
            "ksk_lifetime_days": 0,
            "zsk_lifetime_days": 90,
            "nsec3": False,
        },
    )

    # Manual blocklist + entry + exception (no group needed to create).
    bl = a.call(
        "POST",
        "/api/v1/dns/blocklists",
        json={
            "name": "Corp custom blocks",
            "description": "Manually-curated blocked domains",
            "category": "custom",
            "source_type": "manual",
            "feed_format": "hosts",
            "block_mode": "nxdomain",
            "enabled": True,
        },
    )
    list_id = bl["id"] if bl and bl.get("id") else None
    if list_id is None:
        lists = a.call("GET", "/api/v1/dns/blocklists") or []
        existing = find(lists, "name", "Corp custom blocks")
        list_id = existing["id"] if existing else None
    if list_id:
        a.call(
            "POST",
            f"/api/v1/dns/blocklists/{list_id}/entries",
            json={
                "domain": "ads.example-tracker.com",
                "entry_type": "block",
                "is_wildcard": True,
                "reason": "ad/tracking",
            },
        )
        a.call(
            "POST",
            f"/api/v1/dns/blocklists/{list_id}/exceptions",
            json={"domain": "cdn.allowed-partner.com", "reason": "required CDN"},
        )

    if not dns_group_id:
        print("  · skipping group-scoped DNS sub-resources (no DNS group id)")
        return

    # Split-horizon view.
    a.call(
        "POST",
        f"/api/v1/dns/groups/{dns_group_id}/views",
        json={
            "name": "internal",
            "description": "Internal split-horizon view",
            "match_clients": ["10.0.0.0/8", "192.168.0.0/16"],
            "recursion": True,
            "order": 0,
        },
    )

    # ACL.
    a.call(
        "POST",
        f"/api/v1/dns/groups/{dns_group_id}/acls",
        json={
            "name": "trusted-internal",
            "description": "RFC1918 trusted ranges",
            "entries": [
                {"value": "10.0.0.0/8", "negate": False, "order": 0},
                {"value": "192.168.0.0/16", "negate": False, "order": 1},
            ],
        },
    )

    # TSIG key — omit 'secret' so the server generates one.
    a.call(
        "POST",
        f"/api/v1/dns/groups/{dns_group_id}/tsig-keys",
        json={
            "name": "tsig-update.spatium.local.",
            "algorithm": "hmac-sha256",
            "notes": "DDNS update key",
        },
    )

    # GSLB pool with two inline members on the forward zone.
    if dns_fwd_zone_id:
        a.call(
            "POST",
            f"/api/v1/dns/groups/{dns_group_id}/zones/{dns_fwd_zone_id}/pools",
            json={
                "name": "web-gslb",
                "description": "Health-balanced web frontends",
                "record_name": "app.corp.example.com.",
                "record_type": "A",
                "ttl": 30,
                "hc_type": "tcp",
                "hc_target_port": 443,
                "members": [
                    {"address": "10.10.10.20", "weight": 1, "enabled": True},
                    {"address": "10.10.10.21", "weight": 1, "enabled": True},
                ],
            },
        )

    # Catalog-template zone — resolve a template with no required params so
    # the seeder doesn't have to guess parameter values.
    catalog = a.call("GET", "/api/v1/dns/zone-templates") or {}
    templates = catalog.get("templates", []) if isinstance(catalog, dict) else []
    chosen = None
    for tmpl in templates:
        params = tmpl.get("parameters", [])
        if not any(p.get("required") for p in params):
            chosen = tmpl
            break
    if chosen:
        a.call(
            "POST",
            f"/api/v1/dns/groups/{dns_group_id}/zones/from-template",
            json={
                "template_id": chosen["id"],
                "zone_name": "lab.corp.example.com",
                "params": {},
                "zone_type": "primary",
                "kind": "forward",
            },
        )
    else:
        print("  · skipping template zone (no zero-required-param template in catalog)")


# ── Section: DHCP sub-resources ───────────────────────────────────────────


def seed_dhcp_subresources(a: Api, dhcp_group_id: str | None, scope_id: str | None):
    """Client class, static reservation, MAC block, option template, PXE
    profile, phone profile. All persist without a live Kea agent.
    """
    if not dhcp_group_id:
        print("  · skipping DHCP sub-resources (no DHCP group id)")
        return
    print("Creating DHCP sub-resources…")

    a.call(
        "POST",
        f"/api/v1/dhcp/server-groups/{dhcp_group_id}/client-classes",
        json={
            "name": "voip-phones",
            "match_expression": "substring(option[60].hex,0,9) == 'PXEClient'",
            "description": "Match VoIP vendor class",
            "options": {},
        },
    )

    a.call(
        "POST",
        f"/api/v1/dhcp/server-groups/{dhcp_group_id}/mac-blocks",
        json={
            "mac_address": "00:11:22:33:44:55",
            "reason": "rogue",
            "description": "Unauthorized AP",
            "enabled": True,
        },
    )

    a.call(
        "POST",
        f"/api/v1/dhcp/server-groups/{dhcp_group_id}/option-templates",
        json={
            "name": "Corp DNS+NTP",
            "description": "Standard resolver + NTP options",
            "address_family": "ipv4",
            "options": {
                "domain-name-servers": "10.10.10.20,10.10.10.21",
                "ntp-servers": "10.10.10.5",
            },
        },
    )

    a.call(
        "POST",
        f"/api/v1/dhcp/server-groups/{dhcp_group_id}/pxe-profiles",
        json={
            "name": "netboot-bios+ipxe",
            "description": "BIOS PXE + iPXE chainload",
            "next_server": "10.10.10.5",
            "enabled": True,
            "matches": [
                {
                    "priority": 100,
                    "match_kind": "first_stage",
                    "arch_codes": [0],
                    "boot_filename": "undionly.kpxe",
                },
                {
                    "priority": 50,
                    "match_kind": "ipxe_chain",
                    "boot_filename": "http://10.10.10.5/boot.ipxe",
                },
            ],
        },
    )

    phone_body: dict = {
        "name": "polycom-voip",
        "description": "Polycom TFTP provisioning",
        "enabled": True,
        "vendor": "Polycom",
        "vendor_class_match": "Polycom",
        "option_set": [{"code": 66, "value": "10.10.10.5"}],
        "scope_ids": [scope_id] if scope_id else [],
    }
    a.call(
        "POST",
        f"/api/v1/dhcp/server-groups/{dhcp_group_id}/phone-profiles",
        json=phone_body,
    )

    # Static reservation needs a scope. The IP must be OUTSIDE the seeded
    # dynamic pool (10.10.10.100-149) so the in-pool conflict guard (409)
    # doesn't fire — .50 is clear.
    if scope_id:
        a.call(
            "POST",
            f"/api/v1/dhcp/scopes/{scope_id}/statics",
            json={
                "ip_address": "10.10.10.50",
                "mac_address": "52:54:00:ab:cd:ef",
                "hostname": "printer-lobby",
                "description": "Reserved lobby printer",
            },
        )
    else:
        print("  · skipping DHCP static (no Servers DHCP scope id)")


# ── Section: Governance (RBAC sample + tokens + conformity + webhooks) ─────


def seed_rbac_sample(a: Api):
    """A custom role + non-admin user + group binding them, plus a
    time-bound grant on the group. Ordered role → user → group so the
    group's role_ids / user_ids resolve on first POST.
    """
    print("Creating sample RBAC role + user + group…")

    a.call(
        "POST",
        "/api/v1/roles",
        json={
            "name": "Helpdesk (read-only IPAM+DNS)",
            "description": "Demo delegated role: read-only on IPAM and DNS",
            "permissions": [
                {"action": "read", "resource_type": "ipam"},
                {"action": "read", "resource_type": "dns"},
            ],
        },
    )
    roles = a.call("GET", "/api/v1/roles") or []
    role = find(roles, "name", "Helpdesk (read-only IPAM+DNS)")
    role_id = role["id"] if role else None

    a.call(
        "POST",
        "/api/v1/users",
        json={
            "username": "helpdesk-demo",
            "email": "helpdesk-demo@corp.example.com",
            "display_name": "Helpdesk Demo",
            "password": "DemoPassw0rd!",
            "is_superadmin": False,
            "force_password_change": True,
        },
    )
    users = a.call("GET", "/api/v1/users") or []
    user = find(users, "username", "helpdesk-demo")
    user_id = user["id"] if user else None

    group_body: dict = {
        "name": "Helpdesk",
        "description": "Demo group — delegated read-only operators",
        "auth_source": "local",
        "role_ids": [role_id] if role_id else [],
        "user_ids": [user_id] if user_id else [],
    }
    a.call("POST", "/api/v1/groups", json=group_body)
    groups = a.call("GET", "/api/v1/groups") or []
    group = find(groups, "name", "Helpdesk")
    group_id = group["id"] if group else None

    if not group_id:
        print("  · skipping time-bound grant (no Helpdesk group id)")
        return

    # Time-bound grant — NOT idempotent (no unique constraint), so list-then-
    # skip on a stable (action, resource_type) key to avoid pile-up on re-run.
    existing_grants = (
        a.call("GET", f"/api/v1/groups/time-bound-grants?group_id={group_id}") or []
    )
    already = any(
        g.get("action") == "write" and g.get("resource_type") == "dhcp"
        for g in existing_grants
    )
    if already:
        print("  · time-bound grant already present; skipping")
    else:
        a.call(
            "POST",
            "/api/v1/groups/time-bound-grants",
            json={
                "group_id": group_id,
                "action": "write",
                "resource_type": "dhcp",
                "expires_at": "2030-01-01T00:00:00Z",
                "reason": "Demo: temporary DHCP write for on-call",
            },
        )


def seed_api_token(a: Api, pw: str):
    """A read-only scoped API token. NOT idempotent (no unique name) — guard
    via list-then-skip. The raw token is returned once; we discard it (a
    seeded demo token is never used for real automation). Minting one needs
    the caller's step-up (#1355), so the seeding user's password rides along.
    """
    print("Creating scoped API token…")
    existing = a.call("GET", "/api/v1/api-tokens") or []
    if find(existing, "name", "Ansible inventory (read-only)"):
        print("  · API token already present; skipping")
        return
    a.call(
        "POST",
        "/api/v1/api-tokens",
        json={
            "name": "Ansible inventory (read-only)",
            "description": "Demo automation token — read scope only",
            "expires_in_days": 365,
            "scopes": ["read"],
            "resource_grants": [],
            "stepup_password": pw,
        },
    )


def seed_conformity_policy(a: Api):
    """A custom conformity policy. Gated behind compliance.conformity
    (default-enabled) — tolerate a 404 if the module is off. NOT idempotent
    (no unique name) — guard via list-then-skip. Seeded disabled so the beat
    engine doesn't immediately evaluate it.
    """
    print("Creating custom conformity policy…")
    listed = a.call("GET", "/api/v1/conformity/policies")
    if listed is None:
        # Module likely disabled (404) or another non-200 — skip cleanly.
        print("  · conformity unavailable (module disabled?); skipping")
        return
    if find(listed, "name", "Every subnet has an owner field"):
        print("  · conformity policy already present; skipping")
        return
    a.call(
        "POST",
        "/api/v1/conformity/policies",
        json={
            "name": "Every subnet has an owner field",
            "description": "Demo custom policy: subnets must set the 'owner' custom field",
            "framework": "custom",
            "severity": "warning",
            "target_kind": "subnet",
            "target_filter": {},
            "check_kind": "has_field",
            "check_args": {"field": "owner"},
            "enabled": False,
            "eval_interval_hours": 24,
        },
    )


def seed_webhook(a: Api):
    """A typed-event webhook subscription pointed at a non-resolving host,
    shipped disabled so the worker never attempts delivery. NOT idempotent
    (no unique name) — guard via list-then-skip. Blocked in DEMO_MODE (403),
    which the Api wrapper logs and continues past.
    """
    print("Creating webhook subscription (disabled)…")
    existing = a.call("GET", "/api/v1/webhooks")
    if existing is None:
        # 403 in DEMO_MODE or another non-200 — skip cleanly.
        print("  · webhooks unavailable (demo mode?); skipping")
        return
    if find(existing, "name", "Demo SIEM forwarder"):
        print("  · webhook subscription already present; skipping")
        return
    a.call(
        "POST",
        "/api/v1/webhooks",
        json={
            "name": "Demo SIEM forwarder",
            "description": "Demo typed-event subscription (no live receiver)",
            "enabled": False,
            "url": "https://example.invalid/spatiumddi-hook",
            "event_types": ["subnet.created", "dns.zone.created"],
            "timeout_seconds": 10,
            "max_attempts": 8,
        },
    )


# ── Driver ────────────────────────────────────────────────────────────────


# Feature modules this seeder populates that do NOT ship enabled (#1069).
# The seeder is superadmin, so it turns them on rather than logging a wall
# of 404s and producing a half-empty demo: every one of these gates a
# router this script POSTs to, and ``require_module`` answers 404 when the
# module is off, which ``Api.call`` logs and walks past.
#
# Keep in step with the sections below — a new section whose router is
# module-gated adds its id here, or its data silently never appears.
DEMO_MODULES = (
    "network.asn",
    "network.device",
    "network.customer",
    "network.provider",
    "network.service",
    "network.circuit",
    "network.overlay",
    "network.multicast",
    "compliance.conformity",
)


def enable_demo_modules(a: "Api") -> None:
    """Turn on the gated modules this seeder needs, and say so.

    Idempotent: enabling an already-enabled module is a no-op PATCH. It
    writes a ``feature_module`` row, which is correct — an operator (here,
    this script acting as one) really did change it, and it is the same
    row Settings → Features would write.
    """
    print("== feature modules")
    for module_id in DEMO_MODULES:
        a.call("PATCH", f"/api/v1/admin/feature-modules/{module_id}", json={"enabled": True})
    print(f"  enabled {len(DEMO_MODULES)} module(s) so their demo data is reachable")


def main(base: str, user: str, pw: str):
    token = login(base, user, pw)
    a = Api(base, token)

    enable_demo_modules(a)

    dns_group_id, dns_fwd_zone_id, _dns_rev_zone_id = seed_dns(a)
    dhcp_group_id = seed_dhcp_group(a)

    # ASNs / VRFs come before the IP space so the space's vrf_id /
    # asn_id pointers can resolve on first creation rather than via
    # the re-run patch.
    asns = seed_asns(a)
    seed_peerings(a, asns)
    vrfs = seed_vrfs(a, asns)

    space_id, subnets = seed_spaces_blocks_subnets(
        a,
        dns_group_id=dns_group_id,
        dns_zone_id=dns_fwd_zone_id,
        dhcp_group_id=dhcp_group_id,
        vrfs=vrfs,
        asns=asns,
    )
    seed_addresses(a, subnets)
    dhcp_scope_id = seed_dhcp_scope(a, dhcp_group_id, subnets)

    seed_network_devices(a, space_id)
    seed_legacy_vlans(a)

    seed_domains(a)
    seed_custom_fields(a)
    seed_ipam_templates(a, dns_group_id, dhcp_group_id)

    # IPAM extras — NAT mappings reference seeded subnets/IPs; multicast +
    # subnet plan need the Corporate space id; multicast membership needs
    # an allocated IP in the Servers subnet (already seeded above).
    seed_nat_mappings(a, subnets)
    seed_multicast(a, space_id, subnets)
    seed_subnet_plan(a, space_id)

    # Network modeling — ownership entities first (providers need ASNs;
    # circuits need a provider; services need a customer; overlays + service
    # attaches reference circuits / sites / vrfs / subnets).
    customers = seed_customers(a)
    sites = seed_sites(a)
    providers = seed_providers(a, asns)
    circuits = seed_circuits(a, providers, customers, sites, subnets)
    seed_applications(a)
    seed_services(a, customers, vrfs, sites, circuits, subnets)
    seed_overlays(a, customers, sites, circuits)

    # DNS + DHCP sub-resources — both persist without a live agent.
    seed_dns_subresources(a, dns_group_id, dns_fwd_zone_id)
    seed_dhcp_subresources(a, dhcp_group_id, dhcp_scope_id)

    # Governance + admin data.
    seed_rbac_sample(a)
    seed_api_token(a, pw)
    seed_conformity_policy(a)
    seed_webhook(a)

    seed_alert_rules(a)
    seed_ai_prompts(a)

    print("\n✓ Seed complete.")


if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python3 scripts/seed_demo.py <base_url> <username> <password>")
        sys.exit(1)
    main(sys.argv[1], sys.argv[2], sys.argv[3])
