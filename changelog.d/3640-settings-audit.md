### Fixed

- **Saving a platform setting outside the specially audited sections now
  writes an audit row (#3640).** SSH, resolver, syslog, APT, maintenance,
  supervisor registration, branding, retention and the integration switches
  had their own audit rows; every other setting (password policy, lockout,
  SNMP, NTP, LLDP, DNS and DHCP defaults, session timeouts, the fingerbank
  key and the rest) was saved with a log line only. Each save that changes
  one now adds a single `platform_settings` row with the changed fields and
  their old and new values. Secrets (the fingerbank key, the SNMP community,
  the legacy webhook URL and header) show as set or cleared, never as a
  value, and SNMP v3 users keep the redacted shape.
