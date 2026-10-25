### Fixed

- **Settings written into appliance host configs stay on one line.** The
  SNMP contact and location, the SNMP community, SNMPv3 passphrases, APT
  source suites and firewall rule comments each land in a line-oriented
  host config (snmpd.conf, sources.list, the nftables drop-in), and a
  newline in one of them ended its line, so the rest was read as a
  directive of its own. `PUT /settings` and the firewall rule API now
  answer 422, naming the field, for a newline, carriage return, NUL or
  other control character in these fields (and for whitespace in the
  community, which the `rocommunity` line cannot quote; and for a double
  quote or backslash in a firewall comment). The Operator Copilot's SNMP
  and NTP proposals apply the same checks, and now canonicalise their
  source networks as the REST API does. Each renderer checks again, so a
  value stored before this release is left out (or, for a firewall
  comment, cleaned) with a note in the rendered file rather than written
  as an extra line; snmpd, chrony, apt and nftables keep loading. An
  NTP pool or server name holding NUL or another control character is
  refused as well.
