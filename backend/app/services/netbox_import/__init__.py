"""NetBox read-only one-shot IPAM importer (issue #36).

A migration tool — not a continuous reconciler — that pulls prefixes /
addresses / VLANs / VRFs / tenants / sites out of a live NetBox install
and stamps them into native SpatiumDDI IPAM rows via the same
preview → (stateless round-trip) → commit machinery the DNS (#128) and
DHCP (#129) one-shot importers use.

This package's **Part A** (source reader + IR + mappers; no DB writes):

* :mod:`.client` — async ``httpx`` NetBox client (dual token auth,
  version detect, ``next``-following pagination, retry/throttle, TLS
  toggle, pull ceiling).
* :mod:`.canonical` — neutral IR dataclasses + ``Literal`` enums.
* :mod:`.fetch` — per-endpoint pulls returning normalized raw dicts (the
  NetBox wire-shape / version branch lives here).
* :mod:`.mapping` — pure NetBox-shape → IR mappers (status maps,
  block-vs-subnet decision, multicast detection, ``netbox_id`` stashing).

Part B (``preview.py`` / ``commit.py``) adds the orchestrators:

* :mod:`.preview` — ``preview_netbox_import`` (read-only pull + IR build +
  conflict detection; zero DB writes).
* :mod:`.commit` — source-agnostic ``commit_import`` + ``detect_conflicts``
  (per-row savepoint, audit-before-commit, idempotent re-run, no
  absence-delete; clones the DHCP committer mechanics exactly).

This ``__init__`` re-exports the public surface of both parts.
"""

from __future__ import annotations

from .canonical import (
    ConflictAction,
    EntityConflict,
    ImportedAddress,
    ImportedBlock,
    ImportedCustomer,
    ImportedCustomField,
    ImportedSite,
    ImportedSpace,
    ImportedSubnet,
    ImportedVLAN,
    ImportedVRF,
    ImportPreview,
    ImportSource,
)
from .client import (
    MAX_PAGE_SIZE,
    PULL_CEILING,
    NetBoxClient,
    NetBoxClientError,
)
from .commit import (
    CommitEntityResult,
    CommitResult,
    commit_import,
    detect_conflicts,
)
from .fetch import (
    fetch_aggregates,
    fetch_ip_addresses,
    fetch_ip_ranges,
    fetch_prefixes,
    fetch_regions,
    fetch_rirs,
    fetch_roles,
    fetch_route_targets,
    fetch_site_groups,
    fetch_sites,
    fetch_tenant_groups,
    fetch_tenants,
    fetch_vlan_groups,
    fetch_vlans,
    fetch_vrfs,
)
from .mapping import (
    classify_prefixes,
    map_address,
    map_aggregate,
    map_customer,
    map_prefix_block,
    map_prefix_subnet,
    map_region_as_site,
    map_site,
    map_vlan,
    map_vrf,
)
from .preview import preview_netbox_import

__all__ = [
    "MAX_PAGE_SIZE",
    "PULL_CEILING",
    "CommitEntityResult",
    "CommitResult",
    "ConflictAction",
    "EntityConflict",
    "ImportPreview",
    "ImportSource",
    "ImportedAddress",
    "ImportedBlock",
    "ImportedCustomField",
    "ImportedCustomer",
    "ImportedSite",
    "ImportedSpace",
    "ImportedSubnet",
    "ImportedVLAN",
    "ImportedVRF",
    "NetBoxClient",
    "NetBoxClientError",
    "classify_prefixes",
    "commit_import",
    "detect_conflicts",
    "fetch_aggregates",
    "fetch_ip_addresses",
    "fetch_ip_ranges",
    "fetch_prefixes",
    "fetch_regions",
    "fetch_rirs",
    "fetch_roles",
    "fetch_route_targets",
    "fetch_site_groups",
    "fetch_sites",
    "fetch_tenant_groups",
    "fetch_tenants",
    "fetch_vlan_groups",
    "fetch_vlans",
    "fetch_vrfs",
    "map_address",
    "map_aggregate",
    "map_customer",
    "map_prefix_block",
    "map_prefix_subnet",
    "map_region_as_site",
    "map_site",
    "map_vlan",
    "map_vrf",
    "preview_netbox_import",
]
