### Added

- **RRL on for public-facing groups (#3577).** BIND9 response rate limiting is now on for a DNS server group created as public-facing, and marking an existing group public-facing turns it on too (existing groups are not changed by the upgrade). The Rate limiting card gains the `nxdomains-per-second`, `errors-per-second`, `referrals-per-second`, `nodata-per-second`, `all-per-second`, `ipv4-prefix-length`, `ipv6-prefix-length` and `max-table-size` knobs, which are refused on PowerDNS and Technitium groups.
