### Fixed

- The NAT mappings list, detail and by-IP views no longer show an internal subnet's name and CIDR to a caller who cannot read that subnet; the fields come back null with `internal_subnet_redacted: true`, and the NAT page shows "restricted subnet". `GET /nat-mappings/by-subnet/{id}` answers 403 to a caller without read on that subnet, like the subnet routes (#3641).
