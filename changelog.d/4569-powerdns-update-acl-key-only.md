### Fixed

- **PowerDNS: a dynamic-update grant by TSIG key alone is now accepted** ([#4569](https://github.com/spatiumnorth/spatiumddi/issues/4569)). PowerDNS checks the source address before the key, and with only a key grant the zone allowed loopback alone, so every signed update was refused. A key-only ACL now accepts a signed update from any address. An ACL that mixes IP and TSIG grants is refused (422) on a PowerDNS group: PowerDNS would require the address and the key together, where the ACL means either one. Use TSIG grants only or IP grants only.
