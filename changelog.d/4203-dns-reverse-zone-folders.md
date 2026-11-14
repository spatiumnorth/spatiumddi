### Added

- **DNS zone tree groups reverse zones into folders (#4203).** In a server
  group's zone tree, `in-addr.arpa` and `ip6.arpa` zones now sit under
  two folders, "Reverse zones (IPv4)" and "Reverse zones (IPv6)", each
  with a zone count. The folders come after the forward zones, start
  collapsed, remember open or closed per group, and open by themselves
  when the selected zone is inside one.
