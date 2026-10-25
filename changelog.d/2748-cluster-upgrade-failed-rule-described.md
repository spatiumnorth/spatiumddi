### Fixed

- **The seeded cluster-upgrade-failed rule no longer claims a turned-off
  feature module owns it (#2748).** Its Edit dialog said its type belongs to
  a feature module that is off, and that the server does not describe the
  type, although no module owns it and the upgrade orchestrator evaluates it
  while it is enabled. The rule types list now describes it as platform-driven
  with no parameters, and the New-rule picker still leaves it out.
