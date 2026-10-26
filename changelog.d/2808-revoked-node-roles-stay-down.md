### Fixed

- **A revoked appliance's DNS and DHCP stay down until it is approved again
  (#2808).** The revoked teardown deletes the role chart and keeps the role
  env, so a re-registration can restore the roles. The supervisor's watchdog
  read the roles from that env, found their pods gone and re-applied the
  chart, so a node revoked to take it out of service started DNS and DHCP
  again each time the watchdog fell due (every 5 minutes), until it was
  re-authorized or deleted. The watchdog and the heartbeat's role apply now
  share one gate: only an approved node runs its role services. While a node
  is revoked or pending, its stopped services report `held` in the Fleet
  drilldown rather than a red `missing`, and nothing is re-applied. The first
  accepted heartbeat after approval applies the roles at once, whether or not
  the apply stamp still names the same role env.
