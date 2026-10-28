### Fixed

- **The Features page no longer says agent registration is unaffected
  when DNS or DHCP is turned off (#2950).** The `core.dns` and
  `core.dhcp` descriptions claimed registration was "deliberately
  unaffected", while the turn-off dialog and the API both refuse a new
  agent with a 403 until the module is re-enabled. The refusal is the
  intended behaviour (it stops an agent re-creating a server row right
  after the operator emptied the subsystem), so the descriptions now
  say so: new agents cannot register while the module is off, and
  already-registered agents keep heartbeating and polling their
  config. No behaviour change.
