"""#858 — guard against a field being modelled but never shipped to the agent.

This boundary has now produced the same bug four times:

* #430 — scope ``min_lease_time`` / ``max_lease_time`` and static
  ``client_id`` / ``options_override``: settable, ETag-hashed, read by the
  agent renderer, omitted from the wire payload.
* #856 — the option-name half, on the agent's side of the same boundary.
* #858 — pool ``options_override``, ``pxe_classes`` and ``phone_classes``.
* #858 — pool ``class_restriction``, shipped but never read by the agent.

This test is why #700 wired ``device_policy_classes`` through the payload
and the agent renderer in the same change: adding the dataclass field alone
fails here.

Every occurrence is silent: the UI shows the value, the API returns it, the
ETag moves when it changes so the agent even re-syncs — and the rendered
config is identical, because the payload never carried it.

So this test asserts that every field on ``ConfigBundle`` is *consciously*
classified as either shipped to agents or deliberately withheld. Adding a
field to the dataclass fails here until someone makes that call, which is the
step all four bugs skipped.

It deliberately does NOT assert *how* a field is serialized — the wire shape
and the dataclass shape differ on purpose (the wire synthesizes a ``server``
block, scopes carry a key subset). It asserts only that the decision was made.
"""

from __future__ import annotations

from dataclasses import fields

from app.drivers.dhcp.base import ConfigBundle

# Fields serialized into the agent wire bundle in
# ``app/api/v1/dhcp/agents.py``. Adding one here is a claim that the agent
# receives it; the claim is checked below for the collections that carry
# per-item state.
SHIPPED: frozenset[str] = frozenset(
    {
        "options",  # → "global_options"
        "scopes",
        "client_classes",
        "pxe_classes",
        "phone_classes",
        "device_policy_classes",  # #700
        "mac_blocks",
        "failover",
        "dhcp_socket_type",  # → inside the synthesized "server" block
        "lease_cache_threshold",  # → "server" block (group-wide default)
        "lease_cache_max_age",  # → "server" block
        "kea_thread_pool_size",  # #980 → "server" block
        "kea_packet_logging",  # #980 → "server" block
        "relay_info_retention",  # #54 → "server" block, only when True
        "radvd_conf",
        "ra_configs",
    }
)

# Fields the agent deliberately never receives, each with the reason it is
# withheld rather than forgotten.
WITHHELD: dict[str, str] = {
    "server_id": "the agent knows its own identity from its JWT",
    "server_name": "display-only; the agent has no use for it",
    "driver": "the agent IS the driver — it renders Kea by construction",
    "roles": "control-plane scheduling concern, not daemon config",
    "generated_at": "debug metadata; excluded from the ETag for the same reason",
    "etag": "transport-level, carried in the HTTP header not the body",
}


def test_every_config_bundle_field_is_classified() -> None:
    """A new ConfigBundle field must be shipped or explicitly withheld."""
    declared = {f.name for f in fields(ConfigBundle)}
    classified = SHIPPED | set(WITHHELD)
    unclassified = declared - classified
    assert not unclassified, (
        f"ConfigBundle fields {sorted(unclassified)} are neither in SHIPPED nor "
        "WITHHELD. If the agent needs the field, serialize it in "
        "app/api/v1/dhcp/agents.py AND read it in the agent's render_kea.py, "
        "then add it to SHIPPED. If it is control-plane-only, add it to "
        "WITHHELD with the reason. Skipping this decision is what caused "
        "#430, #856 and #858."
    )


def test_no_stale_entries_in_the_classification() -> None:
    """A removed field must not linger here claiming to be shipped."""
    declared = {f.name for f in fields(ConfigBundle)}
    stale = (set(SHIPPED) | set(WITHHELD)) - declared
    assert not stale, f"{sorted(stale)} no longer exist on ConfigBundle"


def test_withheld_reasons_are_non_empty() -> None:
    """A reason is the whole point — an empty one is an unmade decision."""
    assert all(r.strip() for r in WITHHELD.values())
