### Fixed

- IPAM no longer writes an address's PTR beside a CNAME in the reverse zone (RFC 2317 puts one at an address's label): the PTR is skipped and the skip logged, as for the forward record, and a PTR an earlier release wrote there is retracted on the next sync, so BIND no longer holds the reverse zone on its last good copy ([#4796](https://github.com/spatiumnorth/spatiumddi/issues/4796)).
