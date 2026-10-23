### Changed

- **Most platform settings are superadmin-only on the server, as the
  Settings page already showed them.** A user holding `write` on
  `settings` but not superadmin could change, through
  `PUT /api/v1/settings`, fields the Settings page offers to
  superadmins only, among them `app_base_url`, which builds the URLs
  handed to identity providers at sign-in. Such a delegate may now
  change only IPAM / DNS / DHCP working preferences (utilization
  thresholds, DNS defaults, the DNS auto-sync and pull schedules, DHCP
  lease and domain defaults). Every other field is superadmin-only,
  including session and password policy, appliance host configuration
  (SSH, APT, syslog, SNMP, NTP, LLDP, resolver, timezone) and anything
  that makes an outbound connection. A new field is superadmin-only
  until it is listed as delegate-writable. A request naming any
  superadmin-only field is refused whole with `403` and an audited
  denial, and nothing is written. `PUT /api/v1/settings/resolver` is
  superadmin-only too. Behaviour change for anyone scripting settings
  changes with a non-superadmin `write:settings` account.
