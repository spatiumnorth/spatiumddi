### Fixed

- New DHCP Scope now pre-fills the platform DHCP defaults from its own fresh read of the settings and only with what the scope's address family can carry: an IPv6 scope no longer gets IPv4 DNS / NTP servers or a domain name (which the API refused at Save), and Apply template offers only the templates of that family (#4025, #4026).
