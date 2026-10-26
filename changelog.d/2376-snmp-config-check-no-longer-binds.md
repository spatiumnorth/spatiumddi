### Fixed

- **Appliance SNMP could not be turned on (#2376).** The image's own
  snmpd came up enabled at boot and held UDP 161, and the reload's
  config check kept the staged `agentAddress udp:161` and so always
  collided with it, reporting a valid config as rejected (retried
  forever). snmpd and lldpd are now disabled by a systemd preset as
  well as in the postinst, so nothing listens until the operator opts
  in; and the check parses a copy of the config with its listener and
  AgentX-socket directives removed, so it binds nothing and cannot
  collide with a running snmpd. A genuinely bad config is still
  rejected: the check now reads snmpd's own `line N: Error` output
  whether or not the probe stayed up, because net-snmp logs a bad line
  and keeps running, and a config that passes the check but will not
  start is rolled back to the previous one with snmpd restarted on it.
  And because the image no longer enables snmpd or lldpd, the operator's
  enable link lives only in the `/etc` overlay, which systemd has not
  read when it starts services at boot; a new boot unit starts each
  daemon whose plane is on, so SNMP and LLDP survive a reboot or slot
  upgrade, and their status no longer reads `running` when they are not.
