### Fixed

- A LOC record spelled the way BIND9 accepts (`... 10000m 10m`) is now sent to PowerDNS in the form it accepts (`... 10000.00m 10.00m`), so the record is served and no longer refuses its zone's apply ([#4572](https://github.com/spatiumnorth/spatiumddi/issues/4572)).
