### Fixed

- **Applying a copilot proposal re-checks the permission for conformity
  policies and multicast domains.** The create, update and evaluate
  conformity-policy operations and the create, update and delete
  multicast-domain operations declared no permission, so the apply step did
  not re-check one; only proposing did. A user whose role changed between
  proposing and applying could still apply. They now require what the
  matching REST endpoints require: `admin` on `conformity`, and `write` or
  `delete` on `multicast`. The operations whose REST endpoints are
  superadmin-only (webhooks, DNSSEC sign and unsign, zone update ACL, SNMP,
  NTP and syslog settings, the DNS, DHCP and NetBox import commits, alert
  rules, temporary access, service restart) now declare that too, so the
  apply endpoint refuses a non-superadmin with a 403 before the operation
  runs. A test fails for any operation that declares no gate.
