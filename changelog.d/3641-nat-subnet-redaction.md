### Fixed

- The NAT mappings list, detail and by-IP / by-subnet views no longer show an internal subnet's name and CIDR to a caller who cannot read that subnet; the fields come back null with `internal_subnet_redacted: true` (#3641).
