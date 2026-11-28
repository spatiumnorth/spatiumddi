### Fixed

- **A signed PowerDNS zone's DNSSEC info now lists its keys.** The PowerDNS agent reports each key's tag, type, algorithm and active / published state (read from PowerDNS's cryptokeys) alongside the DS records, on signing, unsigning and the periodic refresh, so `GET .../dnssec/info` no longer returns an empty key list for a zone that has DS records (#4604).
