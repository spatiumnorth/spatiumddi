"""IPAM endpoints a tenant user is refused (#4263, multi-tenancy phase 1).

Every other IPAM endpoint serves tenant users, narrowed to the tenant's spaces
by the session filter (``app.services.tenancy``). These do not, by endpoint
function name, because they act on install-wide DNS / DHCP objects (zones, server
groups, leases, DDNS), on the shared NAT and template catalogues, or send traffic
into the customer's network. DNS and DHCP per tenant are later phases of #695.
"""

from __future__ import annotations

TENANT_REFUSED_IPAM_ENDPOINTS: frozenset[str] = frozenset(
    {
        # effective DNS / DDNS / DHCP inheritance read the install's server groups
        "get_effective_space_dns",
        "get_effective_space_dhcp",
        "get_effective_block_dns",
        "get_effective_block_ddns",
        "get_effective_block_dhcp",
        "get_effective_subnet_dns",
        "get_effective_subnet_ddns",
        "get_effective_subnet_dhcp",
        "list_subnet_writable_zones",
        # IPAM -> DNS reconciliation and reverse-zone creation
        "dns_sync_summary",
        "dns_sync_preview",
        "dns_sync_commit",
        "dns_sync_preview_block",
        "dns_sync_commit_block",
        "dns_sync_preview_space",
        "dns_sync_commit_space",
        "backfill_reverse_zones_subnet",
        "backfill_reverse_zones_block",
        "backfill_reverse_zones_space",
        # DNS record aliases and subnet <-> zone associations
        "list_aliases",
        "add_alias",
        "delete_alias",
        "list_subnet_aliases",
        "list_subnet_domains",
        "add_subnet_domain",
        "remove_subnet_domain",
        # join DHCP leases / fingerprints / network devices, or probe the network
        "get_address_dhcp_fingerprint",
        "profile_address",
        "trigger_subnet_discovery",
        "list_network_context",
        "list_subnet_network_context",
        "get_vendor_rollup",
        "get_vendor_devices",
        "wake_address",
        # shared catalogues
        "list_nat_mappings",
        "create_nat_mapping",
        "get_nat_mapping",
        "update_nat_mapping",
        "list_nat_mappings_for_ip",
        "list_nat_mappings_for_subnet",
        "delete_nat_mapping",
        "list_templates",
        "create_template",
        "get_template",
        "update_template",
        "delete_template",
        "apply_template",
        "reapply_all",
    }
)
