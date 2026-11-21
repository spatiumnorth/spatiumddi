### Fixed

- PowerDNS: names below a DNAME record now answer with the synthesised CNAME instead of NXDOMAIN; the agent renders `dname-processing=yes` in `pdns.conf` ([#4571](https://github.com/spatiumnorth/spatiumddi/issues/4571)).
