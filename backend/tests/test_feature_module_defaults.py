"""The shipped feature-module defaults are a decision, not an accident (#1069).

Which modules are enabled on a FRESH install is product policy. It drifted
once already: the catalog said "default-on so operators discover what
exists", every module's migration seeded a matching row, and the result was
37 of 53 modules — BACnet, DICOM, OT zoning, E911, a BGP looking glass —
in the sidebar of an operator who had not yet created a subnet.

So the shipped value of every module is written out here. Changing one is
then two deliberate edits instead of a keyword nobody reviews, and adding a
module fails this test until somebody states which way it ships.

Two properties make this guard trustworthy where an ordinary import would
not:

* It reads the SOURCE and parses it, so it is immune to
  ``conftest._all_feature_modules_enabled``, which patches every default to
  True for the rest of the suite.
* It needs no database and no app import, so it runs under
  ``pytest --noconftest`` in under a second.
"""

from __future__ import annotations

import ast
from pathlib import Path

_BACKEND = Path(__file__).resolve().parents[1]
_CATALOG = _BACKEND / "app" / "services" / "feature_modules.py"
_VERSIONS = _BACKEND / "alembic" / "versions"


# The shipped default for every module in the catalog. See the "Default
# policy" section of ``app/services/feature_modules.py`` for the criterion
# each of these is derived from.
EXPECTED_DEFAULTS: dict[str, bool] = {
    # ── Core subsystems (#1068) ─────────────────────────────────────
    # These two are the exception to #1069's "default-off unless core
    # workflow" reasoning in the most literal way: they ARE the core
    # workflow. They exist to be switched OFF by the minority of installs
    # that run SpatiumDDI for only one of DNS / DHCP / IPAM, not to be
    # discovered. Flipping either of these to False would ship an install
    # with no DNS or no DHCP out of the box.
    "core.dns": True,
    "core.dhcp": True,
    # ── Network ─────────────────────────────────────────────────────
    "network.customer": False,
    "network.provider": False,
    "network.site": True,
    "network.service": False,
    "network.asn": False,
    # #2325 — off on a FRESH install (it makes off-prem RDAP lookups), but
    # ``default_on_if_rows_in="domain"`` resolves it on wherever Domain rows
    # already exist, as ``ipam.nat`` does. See test_domains_module_gate.py.
    "network.domains": False,
    "network.circuit": False,
    "network.device": False,
    "network.overlay": False,
    "network.vlan": True,
    "network.vrf": True,
    "network.multicast": False,
    "network.av": False,
    "network.bacnet": False,
    "network.e911": False,
    "network.dicom": False,
    "network.ot": False,
    "network.looking_glass": False,
    "ipam.address_sets": True,
    "ipv6.router_advertisements": False,
    # ── AI ──────────────────────────────────────────────────────────
    "ai.copilot": True,
    # ── Compliance ──────────────────────────────────────────────────
    "compliance.conformity": False,
    "reports.top_n": True,
    # ── Tools ───────────────────────────────────────────────────────
    "tools.nmap": False,
    "tools.network": True,
    "tools.pcap": False,
    "tools.wake_scheduler": False,
    # ── DNS ─────────────────────────────────────────────────────────
    "dns.import": True,
    "dns.dynamic_update_acl": True,
    # ── DHCP ────────────────────────────────────────────────────────
    "dhcp.import": True,
    # ── Tools ───────────────────────────────────────────────────────
    "migration.cutover": False,
    # ── IPAM ────────────────────────────────────────────────────────
    "ipam.import.netbox": True,
    # #2100 — off on a FRESH install, but ``default_on_if_rows_in`` resolves
    # it on (without seeding a row) wherever ``nat_mapping`` already holds
    # data, so an upgraded install that uses NAT keeps it. This file pins
    # the fresh-install value; ``test_feature_module_nat_2100.py`` pins the rest.
    "ipam.nat": False,
    # ── Integrations ────────────────────────────────────────────────
    "integrations.kubernetes": False,
    "integrations.docker": False,
    "integrations.proxmox": False,
    "integrations.tailscale": False,
    "integrations.unifi": False,
    "integrations.cloud": False,
    "integrations.opnsense": False,
    "integrations.netbird": False,
    "integrations.paloalto": False,
    "integrations.fortinet": False,
    "integrations.meraki": False,
    # ── Appliance ───────────────────────────────────────────────────
    "appliance.firewall": True,
    # ── Security ────────────────────────────────────────────────────
    "security.certificates": True,
    "security.tls_certs": False,
    "governance.approvals": False,
    "governance.requests": False,
    # ── UI ──────────────────────────────────────────────────────────
    "ui.saved_views": True,
    # ── Security ────────────────────────────────────────────────────
    "security.new_device_watch": False,
    "security.dns_threat": False,
    "security.block_sync": False,
    "security.firewall_feeds": False,
    "security.dnsbl": False,
}


def _catalog_defaults() -> dict[str, bool]:
    """``id -> default_enabled`` parsed out of the catalog source."""
    tree = ast.parse(_CATALOG.read_text(encoding="utf-8"))
    found: dict[str, bool] = {}
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and getattr(node.func, "id", "") == "ModuleSpec"):
            continue
        kwargs = {kw.arg: kw.value for kw in node.keywords}
        ident = kwargs.get("id")
        assert isinstance(ident, ast.Constant), "every ModuleSpec needs a literal id="
        default = kwargs.get("default_enabled")
        if default is None:
            value = True  # the dataclass default
        else:
            assert isinstance(default, ast.Constant), (
                f"{ident.value}: default_enabled must be a literal True/False so this "
                "guard (and a reader) can see the shipped value without running anything"
            )
            value = bool(default.value)
        found[str(ident.value)] = value
    return found


def test_every_module_ships_the_default_this_file_declares() -> None:
    actual = _catalog_defaults()

    unlisted = sorted(set(actual) - set(EXPECTED_DEFAULTS))
    assert not unlisted, (
        f"new feature module(s) {unlisted} are not listed in EXPECTED_DEFAULTS. "
        "Decide explicitly whether each ships enabled — the criterion is in the "
        "'Default policy' docstring of app/services/feature_modules.py — and add "
        "it here. A module that reaches a sidebar because nobody chose is the "
        "#1069 defect."
    )

    removed = sorted(set(EXPECTED_DEFAULTS) - set(actual))
    assert not removed, (
        f"module(s) {removed} are listed here but gone from the catalog. Drop them "
        "from EXPECTED_DEFAULTS in the same change that retires them."
    )

    drifted = {
        mid: {"catalog": actual[mid], "expected": EXPECTED_DEFAULTS[mid]}
        for mid in sorted(actual)
        if actual[mid] != EXPECTED_DEFAULTS[mid]
    }
    assert not drifted, (
        f"shipped default(s) changed without updating this file: {drifted}. If the "
        "change is intended, edit EXPECTED_DEFAULTS in the same commit and say why "
        "in the catalog comment; this is a change to what every fresh install "
        "looks like."
    )


def test_the_default_on_set_stays_small() -> None:
    """A ceiling, not a fixed number.

    The point of #1069 was that the enabled set had grown to 37 of 53 one
    default-on module at a time, each defensible on its own. Nothing stops
    that happening again except a limit someone has to look at.
    """
    on = sorted(mid for mid, enabled in _catalog_defaults().items() if enabled)
    assert len(on) <= 20, (
        f"{len(on)} modules ship enabled: {on}. That is more than #1069 left on "
        "(14, plus the two core subsystems #1068 added) with room to grow. Before "
        "raising this ceiling, check the additions really are core workflow rather "
        "than features that are merely useful."
    )


# Every migration allowed to touch ``feature_module``. All but the last are
# historical seeds: each writes a row at the module's then-default, which is
# exactly what made the catalog's default unreachable, since a row always
# wins. They stay — rewriting applied history fixes nothing — and
# ``a9f2c71e34b8`` is the one that clears them on a fresh install.
_MIGRATIONS_TOUCHING_FEATURE_MODULE: frozenset[str] = frozenset(
    {
        "2c24fe41a7ed_change_requests.py",
        "30135c361a47_netbox_import.py",
        "a3d9f1e64c72_dns_zone_update_acl.py",
        "a3f1d6c92b58_new_device_watch.py",
        "a4f1c93d7e28_windows_cutover_plans.py",
        "a4f81c26b9e3_self_service_requests.py",
        "a7c3e91f4d28_fortinet_meraki_firewall_feeds.py",
        "a7f2c9e4d1b8_acme_client.py",
        "a9f2c71e34b8_feature_module_fresh_install_defaults.py",
        "b2c84f7a91d3_unifi_integration.py",
        "b6f4d2a91c83_opnsense_integration.py",
        "b7e2d9a5f314_dns_import_source.py",
        "b7e4d1a92c30_ipv6_ra_management.py",
        "b8e3f1c47a92_packet_capture.py",
        "c1f4a90e7d63_e911_dispatchable_location.py",
        "c4f7a1d3e589_feature_module_table.py",
        "c7f1a3e58b94_dhcp_import_source.py",
        "c9a4e1f7b820_netbird_integration.py",
        "c9a4f2e81b56_dicom_ae_registry.py",
        "c9f2e1a4d7b6_dnsbl_monitoring.py",
        "cb279a6afd70_bgp_looking_glass_collector_peers_.py",
        "d1a7c34e9b60_dns_client_window.py",
        "d1e7c4a90fb3_cloud_integration.py",
        "d3b9f42a1c05_active_block_sync.py",
        "d4e9f2a7c1b8_saved_views.py",
        "d8b5e4a91f27_integration_feature_modules.py",
        "e2b9c4f1a7d6_address_sets.py",
        "e5a1c39d78b2_vertical_awareness_modules.py",
        "e9c47a1f3b28_wake_scheduler.py",
        "f1e7a3c92b40_multicast_groups.py",
        "f3e8b1d72a9c_tls_cert_monitoring.py",
        "f4a1c9e072d5_panos_integration.py",
        "f5b8d2c91a06_firewall_builtin_seed.py",
    }
)


def test_no_new_migration_seeds_a_feature_module_row() -> None:
    """A seeded row would silently pin the module and re-create #1069.

    ``feature_module`` rows mean "an operator changed this". A migration
    that inserts one makes the catalog default dead on every install that
    runs it — invisibly, because the module still resolves to the value the
    author intended, right up until somebody changes the catalog and
    nothing happens.
    """
    touching = {
        f.name for f in _VERSIONS.glob("*.py") if "feature_module" in f.read_text(encoding="utf-8")
    }
    new = sorted(touching - _MIGRATIONS_TOUCHING_FEATURE_MODULE)
    assert not new, (
        f"migration(s) {new} touch feature_module. A new module does NOT seed a row "
        "(#1069) — set default_enabled in app/services/feature_modules.MODULES and "
        "add it to EXPECTED_DEFAULTS above. If this migration genuinely has to touch "
        "the table, add it to _MIGRATIONS_TOUCHING_FEATURE_MODULE and say why."
    )


# ── requires-chain integrity (#1068) ─────────────────────────────────


def test_every_requires_names_a_real_module_and_the_graph_is_acyclic() -> None:
    """``requires`` is a real gate, so a typo in it silently disables a
    whole feature and a cycle would disable both ends of it.

    ``_resolve_with_parents`` is deliberately forgiving at runtime — an
    unknown parent resolves TRUE so a rename can never black out a
    subtree in production — which means the catalog itself is the only
    place this can be caught.
    """
    from app.services.feature_modules import MODULES

    known = {m.id for m in MODULES}
    for spec in MODULES:
        for parent in spec.requires:
            assert parent in known, (
                f"{spec.id} requires {parent!r}, which is not in the catalog. "
                "At runtime an unknown parent resolves enabled, so this would "
                "fail open and silently."
            )

    # Depth-first cycle detection over the requires edges.
    by_id = {m.id: m for m in MODULES}
    state: dict[str, int] = {}  # 0 = visiting, 1 = done

    def walk(mid: str, path: tuple[str, ...]) -> None:
        if state.get(mid) == 1:
            return
        assert state.get(mid) != 0, f"requires cycle: {' → '.join([*path, mid])}"
        state[mid] = 0
        for parent in by_id[mid].requires:
            walk(parent, (*path, mid))
        state[mid] = 1

    for spec in MODULES:
        walk(spec.id, ())


def test_a_core_subsystem_has_no_parent_of_its_own() -> None:
    """``core.dns`` / ``core.dhcp`` are the roots. Giving either one a
    parent would make the whole subsystem vanish behind some other
    module's toggle, which is not what an operator reading "DNS" expects.
    """
    from app.services.feature_modules import MODULES_BY_ID

    for mid in ("core.dns", "core.dhcp"):
        assert MODULES_BY_ID[mid].requires == (), f"{mid} must stay a root of the requires graph."


def test_every_default_on_if_rows_in_names_a_real_table() -> None:
    """``default_on_if_rows_in`` (#2100) is a probe against a table by name.

    A typo would make the probe raise on every module-state load — every
    gated request — so the table must exist in the model metadata.
    """
    import app.models  # noqa: F401 — registers every table on Base.metadata
    from app.models.base import Base
    from app.services.feature_modules import MODULES

    tables = set(Base.metadata.tables)
    for spec in MODULES:
        if spec.default_on_if_rows_in is None:
            continue
        assert (
            spec.default_on_if_rows_in in tables
        ), f"{spec.id}: default_on_if_rows_in={spec.default_on_if_rows_in!r} is not a table."
