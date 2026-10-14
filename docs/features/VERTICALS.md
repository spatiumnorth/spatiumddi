---
layout: default
title: Vertical network awareness
---

# Vertical network awareness — AV · BACnet/IP · Industrial-OT · DICOM

Umbrella issue [#543](https://github.com/spatiumnorth/spatiumddi/issues/543), with
four children: [#540](https://github.com/spatiumnorth/spatiumddi/issues/540) AV /
Audio-Video-over-IP, [#541](https://github.com/spatiumnorth/spatiumddi/issues/541)
BACnet/IP building automation,
[#542](https://github.com/spatiumnorth/spatiumddi/issues/542) Industrial / OT, and
[#723](https://github.com/spatiumnorth/spatiumddi/issues/723) DICOM (healthcare).

Four IP-native domains that a generic IPAM does not speak. They look unrelated
but they are the **same DDI primitives, specialized**: a uniqueness registry, a
segmentation-documentation layer, and conformity rules over both. Each is a
togglable feature module in the Network group, and all four ship **disabled**
([#1069](https://github.com/spatiumnorth/spatiumddi/issues/1069)) — a registry
means nothing until the site populates it, and a hospital wants DICOM where
nobody else wants the sidebar entries. Turn one on under Settings → Features,
which lists all four with their descriptions whether or not they are enabled.
Enabling one arms nothing: these are registries, with no probing anywhere.

The healthcare research pass concluded there should be **no**
`network.healthcare` catch-all — the vertical splits into separable pieces, and
DICOM is the anchor. The probe-safety piece is
[#722](https://github.com/spatiumnorth/spatiumddi/issues/722), which is not a
vertical at all: it is a constraint on SpatiumDDI's own behaviour and ships
un-gated for every install. See
[Fragile-device probe suppression](#fragile-device-probe-suppression-722).

> **Documentation is in progress.** This covers the shipped Phase 1 of each
> module — the registry, conformity, and UI surfaces. The discovery phases have
> **not** shipped; see [What is deliberately not here](#what-is-deliberately-not-here)
> for why, which is not simply "not yet".

---

## The four at a glance

| | AV over IP (#540) | BACnet/IP (#541) | Industrial / OT (#542) | DICOM (#723) |
|---|---|---|---|---|
| Feature module | `network.av` | `network.bacnet` | `network.ot` | `network.dicom` |
| Sidebar | Network → AV flows | Network → BACnet devices | Network → OT devices | Network → DICOM AEs |
| The differentiating hook | AV descriptor on a multicast group + operator-declared per-protocol ranges | Device instance numbers — a second uniqueness namespace, internetwork-wide | Purdue-level segmentation documented against real subnets | AE Titles — an institution-wide-unique namespace the standard specifies a registry for, and nobody deploys one |
| Protocols | Dante · AES67 · SMPTE ST 2110 (video/audio/anc) · NDI · RAVENNA | BACnet/IP (`UDP 47808`) | PROFINET · EtherNet/IP · Modbus TCP · OPC UA · S7comm · DNP3 · IEC 61850 | DICOM (`TCP 11112` `dicom`, `TCP 104` `acr-nema`) |
| Tables | `av_flow_profile`, `av_reserved_range` | `bacnet_device` | `ot_device`, `ot_zone` | `dicom_ae`, `dicom_peer` |
| Anchored to | `multicast_group` (1:1) | `ip_address` (+ denormalized `subnet_id`) | `ip_address` (1:1), `subnet` (1:1 for zones) | `ip_address` — **nullable**, `SET NULL` (see below) |
| Conformity checks | `av_flow_outside_reserved_range`, `av_flow_no_ptp_domain` | `bbmd_one_per_subnet`, `bacnet_duplicate_device_instance`, `bacnet_vendor_id_unknown` | `ot_device_crosses_purdue_boundary`, `ot_zone_missing_purdue_level` | `dicom_ae_default_title`, `dicom_ae_title_convention`, `dicom_ae_outside_hipaa_scope`, `dicom_ae_no_tls` |
| API prefix | `/api/v1/av/…` | `/api/v1/bacnet/…` | `/api/v1/ot/…` | `/api/v1/dicom/…` |
| RBAC resource type | `av_flow` | `bacnet_device` | `ot_device` | `dicom_ae` |
| Copilot tools | `find_av_flows`, `count_av_flows`, `find_av_reserved_ranges` | `find_bacnet_devices`, `count_bacnet_devices`, `find_bbmds` | `find_ot_devices`, `count_ot_devices`, `find_ot_zones` | `find_dicom_aes`, `count_dicom_aes`, `find_dicom_peers` |

All rows land via the REST API or the UI. **Nothing in this feature family emits
a packet.**

---

## AV / Audio-Video-over-IP (#540)

### It extends the multicast registry, it does not duplicate it

A Dante flow **is** a `MulticastGroup`. AV adds a 1:1 sidecar
(`av_flow_profile`) carrying what the multicast registry has no business
knowing: the AV protocol, the human flow label an engineer reads off a Dante
Controller or 2110 routing panel, and the PTP clock domain.

It is a sidecar rather than columns on `multicast_group` so that a market-data
multicast shop that never enables `network.av` gets no extra columns on a hot
table, and disabling the module is a clean table drop.

> **Module relationship.** `network.av` is only meaningful alongside
> `network.multicast` — an AV flow is a multicast group. There is no
> module-dependency mechanism in the feature-module system, so this is
> documentation rather than an enforced constraint: turning off
> `network.multicast` while leaving `network.av` on leaves the AV surface
> pointing at groups the operator can no longer browse.

### Reserved ranges are what make the checks real

`av_reserved_range` records, per IPSpace, that a CIDR belongs to a given AV
protocol. Best-practice AoIP is *static* multicast assignment, so an operator's
declared plan is the thing worth checking against.

Well-known starting points are offered as presets, **not** auto-inserted — a
vendor default is a default the operator may deliberately have moved off:

| Protocol | Common default |
|---|---|
| Dante | `239.69.0.0/16` |
| AES67 / RAVENNA | a site-chosen block inside `239.0.0.0/8` |
| SMPTE ST 2110 | no standard range — plants carve their own |

`exclusive` distinguishes "this range is *for* Dante and nothing else belongs
here" from "Dante lives here among other things". Most plants want exclusive;
shared exists because small shops run one flat `239.x` range for everything and
would otherwise get a permanent wall of warnings.

`POST /api/v1/av/allocation-preview` answers "would this allocation collide with
another protocol's declared range?" before the operator commits.

### Conformity

- **`av_flow_outside_reserved_range`** — fails when an AV flow's address sits
  outside every range declared for its protocol. **Not applicable** when no
  range is declared for that protocol: absence of policy is not a violation,
  and failing every flow in that state would train operators to ignore the check.
- **`av_flow_no_ptp_domain`** — advisory warn when the clock domain is
  unrecorded. PTP misconfiguration is the most common AoIP failure mode and the
  domain is the first thing asked for when audio drops, but a missing value is
  undocumented state, not a broken network. Applied uniformly across protocols;
  NDI is arguably not PTP-locked the way AES67/2110 are, but the field records
  documentation rather than asserting the flow is clocked, and special-casing it
  would encode a timing claim this registry cannot verify.

---

## BACnet/IP building automation (#541)

### Device instance numbers are the point

Every BACnet device carries a device instance number (0–4,194,302, 22-bit) that
must be unique across the **entire** internetwork — not per-subnet, not
per-site. Duplicate instances are a classic BAS failure that takes days to
trace, and integrators track them in spreadsheets that drift.

That is the same uniqueness-registry problem IPAM already solves for addresses,
applied to a parallel number space — which is what makes it belong in a DDI
rather than a BAS head-end. `uq_bacnet_device_instance` enforces it **in the
database**, not merely in the API, because the failure it prevents is precisely
the one that makes an internetwork misbehave silently.

`4194303` (`0x3FFFFF`) is reserved by the standard as the "unconfigured /
wildcard" instance used in `Who-Is`, so the maximum assignable value is one
below it. The API returns a **409 naming the conflicting device** rather than
surfacing a raw integrity error.

### BBMD topology is a checkable rule

BACnet broadcasts don't cross IP routers, so each IP subnet in a multi-subnet
BACnet/IP network needs **exactly one** BACnet Broadcast Management Device:

- **zero** → that subnet's devices are invisible to the rest of the internetwork
- **two or more** → duplicated broadcast traffic and duplicate `I-Am` responses

`bbmd_one_per_subnet` fails in **both** directions and names the offending
device instances when there are too many. A subnet with no BACnet devices at all
is *not applicable* rather than failing — most subnets in a mixed estate aren't
BACnet subnets, and flagging them would bury the real findings.

`bdt` / `fdt` (Broadcast Distribution Table / Foreign Device Table) are stored
as JSONB snapshots: read-mostly copies of someone else's state that get rendered
and diffed wholesale rather than queried into. Phase 1 accepts them via the API
so a plant can document topology it already knows.

### Vendor labels

`backend/app/services/bacnet/vendors.py` maps well-known ASHRAE vendor ids to
display names. It is deliberately **small**: a wrong label is worse than no
label, because an integrator chasing a duplicate instance who sees the wrong
manufacturer is being actively misled toward the wrong panel, on the wrong
floor, with the wrong vendor's tool. Unresolved ids fall through to the
operator-supplied `vendor_name`. ASHRAE has assigned well over a thousand ids;
full coverage belongs in an importer with provenance, the way OUI data is
handled.

`bacnet_vendor_id_unknown` advises on devices reporting vendor id 0 or none —
0 is legitimately ASHRAE itself, but in the field it almost always means a
misconfigured, cloned, or counterfeit controller.

---

## Industrial / OT (#542)

### Safety posture — read-only identification, permanently

This module identifies and inventories industrial devices. It **never** reads
tags, writes coils or registers, subscribes to OPC UA, or otherwise touches a
control protocol. That is a safety and liability boundary, not a roadmap gap.
Any hint of write access to a control protocol is out of scope, full stop.

It is also explicitly **not** an OT-security product. Deep passive DPI and
anomaly detection are Nozomi / Claroty / Dragos territory; the angle here is DDI
system-of-record plus segmentation documentation.

### PROFINET names are identities

In PROFINET the device *name*, not the IP, is the device's identity: DCP assigns
the address once by name, and a replacement unit is commissioned by giving it
the old name. `profinet_device_name` gets its own indexed column rather than a
custom field because it is a string OT engineers search by.

### Purdue zoning

`ot_zone` records the Purdue level and cell/area for a subnet; `ot_device`
records the level for the device. `purdue_level` is `Numeric(2,1)` rather than an
integer because **level 3.5 — the DMZ between the manufacturing and enterprise
zones — is real and universally used**, and it is exactly the boundary the
conformity check cares most about.

- **`ot_device_crosses_purdue_boundary`** — fails when a device's level differs
  from its subnet's zoned level. A Level-1 PLC in a Level-4 enterprise subnet is
  the finding an auditor asks for. **Not applicable** when either side is unset:
  an unrecorded level is missing documentation, not a violation, and treating
  unknown as guilty would make the check unusable during rollout.
- **`ot_zone_missing_purdue_level`** — advisory; a subnet carrying OT devices but
  no zone row. This is the check that explains an empty segmentation report.

`cell_area` is free text rather than an FK: plants name cells in wildly local
ways and a registry here would be friction with no payoff at this phase.

### CSV import

`POST /api/v1/ot/devices/import/{preview,commit}` ingests engineering-tool
exports (TIA Portal, Studio 5000). Rows key on IP address, and an address that
does not already exist in IPAM is reported as a **row error rather than
created** — this importer enriches inventory, it does not invent it.

Both this importer and the DICOM one below read the text through one shared
CSV reader (`app/services/csv_text.py`): `\n`, `\r\n` and a bare `\r` (classic
Mac line endings) are all accepted, and text the csv module cannot read (a cell
over its field size limit, say) is a 422 that gives the reason rather than a
500 (#1370, #1711).

---

## DICOM — medical imaging (#723)

### AE Titles are the textbook uniqueness registry

A DICOM **Application Entity Title** is a flat, institution-wide-unique,
16-byte identifier. Every modality, PACS node, workstation and archive answers
to one, and every peer that wants to talk to it must have that exact string
configured. Duplicates break C-MOVE, Storage Commitment, Modality Worklist and
MPPS, and the failure has been documented since 1997 with an unchanged root
cause: vendor defaults nobody changed.

DICOM PS3.15 Annex H defines `dicomUniqueAETitlesRegistryRoot` — an LDAP
registry object whose *only* purpose is allocating unique AE Titles via a
compare-and-set against an enforced constraint. It is essentially undeployed. In
practice the namespace lives in a spreadsheet.

That is the BACnet device-instance argument with better provenance: the standard
itself says the value must be unique and specifies a registry for it, and no
incumbent system owns the namespace. So `uq_dicom_ae_title` is the point of the
table, not an incidental index — and a collision answers **409 naming the AE
that already holds the title**, because the conflicting row is usually in
another department, commissioned by another vendor's engineer.

Contrast with the rest of healthcare, which is why there is no
`network.healthcare` module: HL7/MLLP port sprawl is real but the interface
engine owns it; FHIR is HTTPS with path-based discovery; WMTS is not IP at all.

### The anchor is nullable, on purpose

`dicom_ae.ip_address_id` is nullable with `ON DELETE SET NULL` — deliberately
unlike `bacnet_device`'s `CASCADE`. **An AE Title outlives the host it runs
on.** It is burned into peer configuration across the estate, so decommissioning
an IP must demote the title to a *reservation*, not free a name a dozen
modalities still send to. Cascading would hand it straight to the next
commissioning engineer.

An unbound AE is therefore a normal, first-class state: the list has a
"Reservations only" filter, the API a `?unbound=true` query, and the UI a
`reservation` badge.

### AE Title validation — 16 bytes, and spaces are legal

The `AE` value representation is easy to get wrong in the strict direction, and
strict is the worse failure: a registry that rejects a title real devices use
records a plan that fails at commissioning. `services/dicom/titles.py` implements
PS3.5 verbatim:

- maximum **16 bytes** — bytes, not characters, so a non-ASCII title can be over
  the limit at 15 characters;
- **spaces are legal** but non-significant (they are padding), so leading and
  trailing space is trimmed and internal spaces are kept;
- an **all-space value is forbidden**, which after trimming is the same
  statement as "must not be empty";
- backslash (`0x5C`, the multi-value delimiter) and all control characters are
  excluded.

There is no alphanumeric-only rule and no case rule. Case *is* significant to
peers, so titles are stored as given and matched exactly; only the
vendor-default advisory compares case-insensitively.

### Peers make renumbering answerable

`dicom_peer` is a directed AE→AE edge describing a **configured** association —
documented by the operator or imported, never inferred from traffic, which would
mean parsing DICOM that carries PHI. Direction is load-bearing: an AE's
*outbound* edges stop sending when it moves, its *inbound* edges stop being able
to reach it, and those are different remediation lists. `GET
/api/v1/dicom/aes/{id}/impact` returns them split.

### Conformity

| Check | Target | Verdict |
|---|---|---|
| `dicom_ae_default_title` | platform | **Warn** when any AE is still on a known vendor default (`DCM4CHEE`, `ANY-SCP`, `ORTHANC`, …). Not invalid — just the most common cause of estate-wide collisions. |
| `dicom_ae_title_convention` | platform | **Fail** for titles that don't match the institution's naming convention, supplied as a `pattern` check **argument** rather than a table: every site's convention differs, and a convention registry would be a schema for one regular expression. Not-applicable when no pattern is set. |
| `dicom_ae_outside_hipaa_scope` | platform | **Fail** for a bound AE in a subnet not flagged `hipaa_scope`. DICOM carries ePHI, so either the scope flag or the device placement is wrong. Reservations and unknown-subnet rows are excluded — an unknown is an unknown. |
| `dicom_ae_no_tls` | platform | **Warn** for AEs not recorded as TLS-enabled. Reports what the *registry* records, not what the wire does; remediation is a device-by-device project with clinical downtime, so a hard fail on day one would put every hospital permanently red. Raise the severity once that project is done. |

### Import

`POST /api/v1/dicom/aes/import/{preview,commit}` ingests the estate's existing
AE table. Two contracts differ from the OT importer:

- **The join key is `ae_title`, not the IP** — that is the identity DICOM cares
  about and the one the unique constraint is on. Two rows in one file sharing a
  title is a per-row error, because that duplicate is the exact collision the
  registry exists to surface.
- **The address column is optional.** A blank address registers an unbound
  reservation rather than failing. A *supplied* address IPAM doesn't know is
  still an error — an export enriches inventory, it does not invent it.

### Hard guardrail — no PHI, ever

The registry stores **network identity only**: titles, hosts, ports, roles,
vendors, departments. It records nothing about patients, studies or images.
Storing patient-identifiable data would make SpatiumDDI a HIPAA Business
Associate, which is permanently out of scope. `notes` is documented on the wire
as a network-configuration field, because an unlabelled free-text box is the
surest way to end up storing PHI by accident.

---

## Fragile-device probe suppression (#722)

Not a vertical, and deliberately **not** behind a feature module: it is a
constraint on SpatiumDDI's own behaviour and a correctness fix to three shipped
features, so it is on for every install.

Medical- and OT-device vendors explicitly instruct sites not to scan their
VLANs — Swisslog's pneumatic-tube deployment guide says to omit ping sweeps and
nmap of any range supporting the PTS, and the same hazard covers patient
monitors, BMC / IPMI endpoints, and the PLC / RTU class `network.ot` registers.
Fragile IP stacks fault or drop off the network under a sweep. Until this flag
existed there was no way for an operator to say so.

`do_not_probe` + `do_not_probe_reason` live on `IPSpace`, `IPBlock` and
`Subnet`, and **OR down the chain**. That is deliberately unlike the DDNS fields
they otherwise mirror, which resolve to the first non-inheriting ancestor and so
let a descendant override its parent. A hospital that marks its clinical
IPSpace do-not-probe must not have one subnet quietly opt back in, so there is
no per-level inherit toggle and nothing downstream can un-set the flag. The
*nearest* flagged level supplies the reason, because that is the most specific
explanation an operator wrote.

**Every probe origin consults the same resolver**
(`app/services/ipam/probe_policy.py`):

| Origin | Behaviour |
|---|---|
| #23 discovery sweep | Skipped before any packet, `last_discovery_at` stamped so the dispatcher stops re-queueing, reason recorded on the audit row. The dispatcher also skips flagged subnets so a flagged estate doesn't generate a task per subnet per interval. |
| `tools.nmap` | 422 before the scan row is persisted. Covers CIDR targets in both directions — a `/16` sweep reaches a flagged `/24` inside it, and a `/25` inside a flagged `/16` is equally covered. |
| `tools.nmap` auto-profile on DHCP lease | Checked before the refresh window, so it cannot be bypassed by tuning the other guards. |
| `tools.network` ping / traceroute / mtr / port-test / tls-cert | 422 with the operator's reason quoted back. Gated before the vantage branch, so an appliance-vantage run is refused identically — the hazard is packets reaching the device, not which host emits them. |
| "Re-profile now" on an IP | 422. It bypasses the refresh window on purpose; it does not bypass this, because the operator who clicked it is usually not the one who wrote the vendor bulletin onto the subnet. |
| Operator Copilot | Both the `run_nmap_scan` apply path and the `network_ping` / `network_traceroute` / `network_port_test` / `network_tls_cert` MCP tools. A proposal the operator approved is still a scan, and the copilot must not be the one surface that still probes. No override on either — clearing the flag is a deliberate superadmin action on the tools page, not something to talk a copilot into. |
| TLS certificate probes (#118) | The 6-hourly sweep skips flagged targets, and so does the probe dispatched on target create. A TLS handshake is an active probe, and a BMC or imaging console answering 443 is exactly the protected class. |
| SNMP polling | Skipped, with `next_poll_at` deliberately left where it was — the poll did not happen, so nothing about its schedule should move. A GET is still a packet we originated. |
| Scheduled Wake-on-LAN verification (#586) | The **active** chain only. Passive verification still runs, so a suppressed host is still verified — from sightings that already happened, without a packet being sent at it. Waking a fragile device is fine; poking it to confirm is not. |

`dig`, `whois`, DNS-propagation and mac-vendor are **not** gated: they query a
resolver or an off-prem service about a name, they do not probe the name's host.
Passive collection is untouched by design — PCAP (#59), DHCP fingerprinting, RA
sniffing and ARP-table reads observe traffic that already exists.

**The override.** `override_do_not_probe: true` requires **superadmin** — not a
permission grant, because `use_network_tools` is a routine grant delegated
admins hold and the point of the flag is that whoever clears it is accountable.
It writes a `probe.do_not_probe_override` audit row *before* the probe runs, and
it is per-request: nothing is remembered, so the next call is refused again. The
alternative — refusing absolutely — just gets the flag turned off estate-wide,
which is a worse outcome than a recorded exception.

**Fail-safe direction.** A target the resolver cannot map to a subnet is
*allowed*. Refusing everything unmappable would make the tools page unusable
against off-IPAM infrastructure, and an operator who never modelled a network in
IPAM never told us it was fragile. Hostnames are matched against
`IPAddress.hostname` rather than resolved through DNS: a lookup inside an
authorization check makes the verdict depend on a round-trip nobody can see the
result of, and lets a hostile record steer the guard.

**The conformity check works backwards from the registries.** The flag is
opt-in, so `fragile_subnet_probed` (target: subnet) **fails** when a subnet
carries registered `ot_device` rows, `dicom_ae` rows, or `role="bmc"` addresses
but is not covered by the flag — if an operator has told us a subnet holds that
gear, they have already told us it is fragile. Suppression inherited from a
parent counts as covered.

`bmc` also joins the `IP_ROLES` set in the same issue: BMC / IPMI / Redfish
endpoints are exactly this fragile class, and naming them is what lets an
operator find every one and decide whether their subnet belongs behind the flag.

---

## What is deliberately not here

Every discovery phase across all three modules is unshipped, and the reasons are
structural rather than scheduling.

**The umbrella's shared dependency was cancelled.** #543 named
[#40](https://github.com/spatiumnorth/spatiumddi/issues/40) (mDNS / Bonjour / WSD
passive discovery) as "the common enabling primitive; worth landing early". #40
was **closed as not planned** after a feasibility review, which found that
mDNS/WSD are link-local multicast — only a host-networked, on-segment agent
hears anything, and the agent↔subnet binding that would require is not modelled
today.

| Deferred | Why |
|---|---|
| #540 Phase 2 — Dante mDNS discovery | Blocked at the source. Dante discovery *is* mDNS, and #40 is closed. |
| #540 Phase 3 — NMOS IS-04 mirror | A full read-only pull integration with its own reconciler and both dashboard surfaces (non-negotiable #15). Cleanly separable; deserves its own change. |
| #541 Phase 2 — `Who-Is` sweep | Needs a UDP broadcast carrying a real BACnet payload. The control plane's only generic UDP prober sends an **empty** datagram, so this needs a new datagram helper plus the same agent↔subnet binding #40 died on. |
| #542 Phase 2 — EtherNet/IP · Modbus · OPC UA probes | The issue expected this to be nearly free via nmap NSE scripts. It is not: nmap **runs** `--script enip-info,modbus-discover` today, but `_parse_host()` never reads `<script>` / `<hostscript>` elements, so the output dies in `raw_xml`. Real discovery needs an NSE-output parser plus a preset threaded through five separate hardcoded lists. |
| #542 Phase 3 — PROFINET DCP | Ethertype `0x8892`, raw L2, not routable. No `SOCK_RAW` code exists in the backend and `CAP_NET_RAW` is a file capability on the `nmap`/`tcpdump` binaries only — the Python process does not have it. Needs a container capability grant, i.e. a deployment change. |
| #723 — C-ECHO verification probe | Filed separately. It is the **one** probe in this family that does *not* inherit the agent↔subnet blocker — C-ECHO is routable unicast TCP, so it could run from the control plane today. It is deferred on its own merits (an association negotiation is a real DICOM client, not a socket poke) and it must go through #722's do-not-probe gate first: a probe reaching a modality mid-study is precisely the hazard that flag exists for. |

Each phase remains worth doing; each is its own piece of work with its own
prerequisites, and none of them is a metadata phase.

**Also permanently out of scope:** patient-identifiable data of any kind (see
the DICOM PHI guardrail above) and inferring DICOM associations from captured
traffic; RTP jitter / packet-loss / SDP essence
analysis and NMOS IS-05 connection control (SpatiumDDI is a registry, not a
media monitor); running PIM/IGMP or acting as a BBMD (we document the topology,
we don't participate in it); BACnet object/point-level management (we track the
device, not its 600 objects); and BACnet MS/TP or other serial datalinks, which
aren't IP-addressable.

---

## Operational notes

- **Backup / factory reset.** The seven tables — plus the four multicast tables
  they depend on — are covered by the `verticals` backup section and the
  `DESTROY-VERTICALS` factory-reset section. Resetting the verticals section
  destroys only the vertical metadata; the underlying IPAM addresses and subnets
  are untouched.
- **RBAC.** The builtin **Network Editor** role grants `admin` on `av_flow`,
  `bacnet_device`, `ot_device`, and `dicom_ae`. Builtin roles are re-seeded on
  every boot, so no migration is involved. `do_not_probe` (#722) is a field on
  the IPAM rows and needs no resource type of its own — editing it requires
  write on the space / block / subnet, and *overriding* it requires superadmin.
- **Enum vocabularies** (`av_protocol`, `ot_protocol`, `ot_role`, `role`,
  `device_class`, `seen_via`) are
  module-level `frozenset[str]` validated at the API layer rather than Postgres
  enums, matching the multicast registry's convention — adding a protocol later
  must not require a migration. Values with a *specification-defined* range
  (BACnet's 22-bit instance space, PTP's single octet, Purdue 0–5, the DICOM
  16-byte AE length ceiling and its port range) do carry database `CHECK`
  constraints, because those bounds will never move.
- **`seen_via`** already accepts the discovery-phase values (`mdns`, `nmos`,
  `whois`, `enip`, `dcp`, `echo`, …) so those phases need no data migration.
