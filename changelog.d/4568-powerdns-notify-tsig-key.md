### Fixed

- **A PowerDNS primary's NOTIFY is accepted by a secondary granted by
  address (#4568).** The agent listed every TSIG key of the group in
  each zone's `TSIG-ALLOW-AXFR`, and PowerDNS signs its outgoing NOTIFY
  with a key from that list. A secondary without the key, one granted
  by address or an external one, rejected every NOTIFY and picked up
  changes only at its SOA refresh. A key is now listed only when the
  zone's allow-transfer (or the server's, when the zone sets none)
  names it as `key <name>`. A secondary that transferred from a
  PowerDNS server with a group key the list does not name needs that
  key added to allow-transfer.
