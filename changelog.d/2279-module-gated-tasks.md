### Fixed

- **Turning a feature module off now stops its scheduled work, not
  just its pages (#2279).** A disabled module's router answered 404,
  but several of its Celery tasks never asked whether it was on. So
  after an operator switched a module off, SpatiumDDI kept going:
  nmap scans of each new DHCP client in a subnet with auto-profile
  set, SNMP polls (`network.device`), TLS probes
  (`security.tls_certs`), conformity runs (`compliance.conformity`),
  and the off-prem RDAP, RPKI and RIPEstat fetches behind
  `network.asn`. Every module-owned beat task now goes through one
  gate, `@module_gated(...)` in `app/tasks/module_gate.py`, which
  reuses the module resolver, so a disabled parent module (`requires=`)
  stops its children's tasks too. While the module is off, a task does
  nothing and logs the skip once at debug. The DHCP lease hook no
  longer profiles new clients with `tools.nmap` off, and
  `POST /ipam/addresses/{id}/profile` answers 404, as `/nmap` does.
  The Fortinet and Meraki sweeps now follow their modules too. Before,
  they read only their own `integration_*_enabled` setting, which the
  module toggle does not update. Core, retention and prune tasks run
  regardless. Each one is listed with its reason in
  `UNGATED_BEAT_TASKS`, and a guard test fails any beat task that is
  neither gated nor listed. `PRIVACY.md` now names the module behind
  the BGP / RPKI enrichment hosts. It used to cite `bgp.*` modules,
  which do not exist. Its ASN and ROA refresh rows (#2280) said
  those tasks ignore `network.asn`; with this change they stop while
  it is off, and the rows now say so.
