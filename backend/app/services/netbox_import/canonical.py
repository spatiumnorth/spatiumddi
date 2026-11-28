"""Canonical IR shared by the NetBox one-shot importer (issue #36).

The NetBox source reader (``fetch.py`` + ``mapping.py``) pulls upstream
IPAM / tenancy / dcim-org objects and maps them onto this neutral shape
so the commit endpoint can stay source-agnostic — exactly the contract
:mod:`app.services.dns_import.canonical` establishes for the DNS
importers. The shape is deliberately a strict subset of what the IPAM
ownership / network tables carry: enough to recreate each row faithfully,
no source-specific extensions. Anything NetBox carries that we can't
model lands in :attr:`ImportPreview.warnings` so the UI can surface it on
the preview rather than dropping it silently.

Two deliberate narrowings vs the DNS IR (issue body §4.3):

* :data:`ImportSource` is ``"netbox"`` or ``"phpipam"`` (#4734; the DNS IR is
  an 11-value Literal because cloud providers stamp their provider name).
* :data:`ConflictAction` is ``skip | overwrite`` with **no ``rename``** —
  NetBox entities are CIDR / rd / name-keyed and can't be renamed (the
  DHCP importer's IR makes the same narrowing for the same reason).

Every created row is also stamped with its NetBox primary key
(``custom_fields["netbox_id"]`` where the model has a ``custom_fields``
column, else ``tags["netbox_id"]``; VLAN has neither, so its only
idempotency anchor is the ``import_source`` / ``imported_at`` provenance
columns the migration adds — see ``netbox_ctx/03_models.md``). The IR
carries ``netbox_id`` as a plain field on every dataclass that maps to a
created row; the committer decides where it lands per-model.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

# Stable enum the importer stamps on every row it creates; the value goes
# into the ``import_source`` String(20) column. Kept as a Literal (not a bare
# str) so the source label stays type-honest with the DNS / DHCP importer
# convention. ``phpipam`` (#4734) builds the same IR from a different
# source reader and commits through the same pipeline; the IR field named
# ``netbox_id`` carries that source's primary key either way (the name is the
# #36 wire shape and stays).
ImportSource = Literal["netbox", "phpipam"]

# Per-entity conflict resolution. NO ``rename`` — NetBox entities are
# keyed by CIDR / rd / name and can't be renamed (mirrors the DHCP
# importer's ``ConflictAction``). Default ``skip`` so a fat-fingered
# "Commit" never tramples an existing row.
ConflictAction = Literal["skip", "overwrite"]


@dataclass
class ImportedCustomer:
    """A NetBox tenant → SpatiumDDI ``Customer`` (ownership FK, not the
    space boundary).

    ``name`` is the upsert key (UNIQUE on ``customer.name``). ``notes``
    folds NetBox ``tenant.description``. ``custom_fields`` merges NetBox
    custom fields; ``netbox_id`` rides in ``custom_fields`` on commit
    (Customer has a ``custom_fields`` column). ``tags`` carries
    ``netbox_tenant_group`` (Customer has no parent FK).
    """

    name: str
    notes: str = ""
    custom_fields: dict[str, Any] = field(default_factory=dict)
    tags: dict[str, Any] = field(default_factory=dict)
    netbox_id: int | None = None


@dataclass
class ImportedSite:
    """A NetBox site → SpatiumDDI ``Site`` (tree node).

    ``code`` is NetBox ``slug`` (unique per parent, ``"" → NULL``).
    ``parent_code`` references the parent site's ``code`` (region is the
    primary parent axis; site-group folds to ``tags``). Site has **no**
    ``custom_fields`` column, so ``netbox_id`` rides in ``tags`` on
    commit.
    """

    name: str
    code: str | None = None
    parent_code: str | None = None
    kind: str = "datacenter"
    region: str | None = None
    notes: str = ""
    tags: dict[str, Any] = field(default_factory=dict)
    netbox_id: int | None = None


@dataclass
class ImportedVRF:
    """A NetBox VRF → SpatiumDDI ``VRF``.

    Upsert key #1 is ``rd`` (``route_distinguisher``) when present, #2 is
    ``name`` (UNIQUE). ``import_targets`` / ``export_targets`` are the
    ``[rt.name …]`` lists. ``customer_name`` resolves to ``customer_id``
    via the customer pass. ``netbox_id`` rides in ``custom_fields``.
    """

    name: str
    rd: str | None = None
    import_targets: list[str] = field(default_factory=list)
    export_targets: list[str] = field(default_factory=list)
    description: str = ""
    customer_name: str | None = None
    custom_fields: dict[str, Any] = field(default_factory=dict)
    tags: dict[str, Any] = field(default_factory=dict)
    netbox_id: int | None = None


@dataclass
class ImportedSpace:
    """A SpatiumDDI ``IPSpace`` synthesized per VRF (+ one ``"Global"``
    for the vrf=null table and aggregates).

    Not a 1:1 NetBox object — it's derived from the space strategy. Links
    the created ``VRF`` row via ``IPSpace.vrf_id`` (``vrf_name``).
    ``is_default`` flags the Global space (reuse an existing default
    space if present). IPSpace has **no** ``custom_fields`` column, so
    any ``netbox_id`` rides in ``tags`` on commit (the Global space has
    none — it's not a NetBox object).
    """

    name: str
    vrf_name: str | None = None
    is_default: bool = False
    customer_name: str | None = None
    description: str = ""
    tags: dict[str, Any] = field(default_factory=dict)


@dataclass
class ImportedVLAN:
    """A NetBox VLAN → SpatiumDDI ``VLAN`` under a synthesized ``Router``.

    Uniqueness is ``(router_id, vid)`` + ``(router_id, name)`` under the
    single synthetic router. VLAN has **neither** ``tags`` nor
    ``custom_fields`` — its only idempotency anchor on re-import is the
    ``import_source`` / ``imported_at`` provenance columns + the
    ``(router_id, vid)`` / ``(router_id, name)`` keys, so ``netbox_id`` is
    carried for the preview / audit only, not stored on the row.
    """

    vid: int
    name: str
    description: str = ""
    netbox_id: int | None = None


@dataclass
class ImportedBlock:
    """A NetBox aggregate / container-or-enclosing prefix → ``IPBlock``.

    ``space_name`` selects the target ``IPSpace`` (per-VRF or Global).
    ``parent_cidr`` references the enclosing block's CIDR for nesting
    (``None`` = top-level). ``netbox_id`` rides in ``custom_fields``.
    """

    network: str  # CIDR
    name: str = ""
    description: str = ""
    space_name: str | None = None
    parent_cidr: str | None = None
    customer_name: str | None = None
    site_code: str | None = None
    custom_fields: dict[str, Any] = field(default_factory=dict)
    tags: dict[str, Any] = field(default_factory=dict)
    netbox_id: int | None = None


@dataclass
class ImportedSubnet:
    """A NetBox leaf prefix → SpatiumDDI ``Subnet``.

    ``status`` is the mapped ``Subnet.status`` (``active`` / ``reserved``
    / ``deprecated``). ``vlan_vid`` links the prefix's VLAN via
    ``Subnet.vlan_ref_id`` (resolved through the VLAN pass). ``kind`` is
    the ``unicast`` / ``multicast`` discriminator. ``subnet_role`` is set
    only when the NetBox prefix role maps to ``data|voice|management|
    guest``; otherwise the raw role lands in ``custom_fields``.
    ``netbox_id`` rides in ``custom_fields``.
    """

    network: str  # CIDR
    name: str = ""
    description: str = ""
    space_name: str | None = None
    status: str = "active"
    vlan_vid: int | None = None
    customer_name: str | None = None
    site_code: str | None = None
    subnet_role: str | None = None
    kind: str = "unicast"
    custom_fields: dict[str, Any] = field(default_factory=dict)
    tags: dict[str, Any] = field(default_factory=dict)
    netbox_id: int | None = None


@dataclass
class ImportedAddress:
    """A NetBox IP address → SpatiumDDI ``IPAddress``.

    ``address`` has its ``/mask`` stripped (the mask only locates the
    enclosing subnet). ``status`` is the mapped operator-settable status
    (``allocated`` / ``reserved`` / ``deprecated``). ``role`` is set only
    when the NetBox IP role is in the SpatiumDDI role enum; otherwise the
    raw role lands in ``custom_fields["netbox_role"]``. ``subnet_cidr``
    is the NetBox-reported enclosing CIDR (the committer resolves the
    most-specific imported subnet). ``netbox_id`` rides in
    ``custom_fields``; conflict / upsert key is ``(subnet_id, address)``.
    """

    address: str
    status: str = "allocated"
    role: str | None = None
    hostname: str | None = None
    fqdn: str | None = None
    description: str = ""
    subnet_cidr: str | None = None
    space_name: str | None = None
    mac_address: str | None = None
    custom_fields: dict[str, Any] = field(default_factory=dict)
    tags: dict[str, Any] = field(default_factory=dict)
    netbox_id: int | None = None


@dataclass
class ImportedCustomField:
    """A source custom-field definition → ``CustomFieldDefinition``.

    Created only when ``(resource_type, name)`` is free; an existing
    definition is left as it is (conflict key ``custom_field:<type>:<name>``),
    so the import never reshapes a field operators already use. ``name`` is
    the sanitised key the row values are stored under; ``source_name`` is what
    the source called it.
    """

    resource_type: str  # ip_block | subnet | ip_address
    name: str
    label: str
    field_type: str = "text"
    options: list[str] | None = None
    source_name: str = ""


@dataclass
class EntityConflict:
    """An imported entity whose key already exists in the target.

    ``kind`` is the entity type (``ip_space`` / ``ip_block`` / ``subnet``
    / ``ip_address`` / ``vrf`` / ``vlan`` / ``customer`` / ``site``).
    ``key`` is the stable per-kind conflict key (VRF rd|name, space name,
    block CIDR, subnet canonical CIDR, ip ``subnet_cidr+address``).
    ``existing_id`` is the colliding row's UUID (as str). ``reason`` is
    an operator-facing one-liner. ``action`` is the operator's per-row
    decision (default ``skip`` so an untouched conflict never tramples).
    """

    kind: str
    key: str
    existing_id: str  # uuid as str
    reason: str
    action: ConflictAction = "skip"


@dataclass
class ImportPreview:
    """What ``POST /ipam/import/netbox/preview`` returns.

    Carries the **full** canonical IR across every entity type — the
    commit endpoint re-receives it from the operator (the UI passes it
    back verbatim as ``CommitIn.plan``) so the server stores nothing
    server-side between the two calls (the same stateless round-trip the
    DNS / DHCP importers use). ``conflicts`` is advisory on the preview;
    the committer re-detects fresh against up-to-date state at commit
    time. ``counts`` is the per-entity-type rollup for the preview UI.
    """

    source: ImportSource
    customers: list[ImportedCustomer] = field(default_factory=list)
    sites: list[ImportedSite] = field(default_factory=list)
    vrfs: list[ImportedVRF] = field(default_factory=list)
    spaces: list[ImportedSpace] = field(default_factory=list)
    vlans: list[ImportedVLAN] = field(default_factory=list)
    blocks: list[ImportedBlock] = field(default_factory=list)
    subnets: list[ImportedSubnet] = field(default_factory=list)
    addresses: list[ImportedAddress] = field(default_factory=list)
    custom_field_defs: list[ImportedCustomField] = field(default_factory=list)
    conflicts: list[EntityConflict] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def counts(self) -> dict[str, int]:
        """Per-entity-type create count for the preview UI."""
        return {
            "customers": len(self.customers),
            "sites": len(self.sites),
            "vrfs": len(self.vrfs),
            "spaces": len(self.spaces),
            "vlans": len(self.vlans),
            "blocks": len(self.blocks),
            "subnets": len(self.subnets),
            "addresses": len(self.addresses),
            "custom_fields": len(self.custom_field_defs),
            "conflicts": len(self.conflicts),
        }
