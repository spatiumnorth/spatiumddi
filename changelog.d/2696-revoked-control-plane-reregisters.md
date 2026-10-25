### Fixed

- **A control-plane node whose Fleet row goes away registers again
  without a restart (#2696).** Its supervisor flipped to revoked after
  two refused heartbeats and stayed revoked, with its DNS and DHCP
  services torn down, until its pod restarted, because the recovery
  that registers it again ran only at start-up. The running supervisor
  now runs it too. It asks the self-bootstrap for a fresh code before
  it clears anything, so a node whose row is still there (its
  heartbeats refused while appliance registration is switched off, for
  example) keeps its identity and is approved again on the same row
  once its heartbeats are accepted. Data-plane appliances keep their
  identity as before, so Re-authorize on the Fleet page still restores
  them.
