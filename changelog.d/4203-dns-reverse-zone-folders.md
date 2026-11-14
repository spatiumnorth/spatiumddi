### Added

- **DNS zone lists group reverse zones into folders (#4203).** In a
  server group's zone tree, `in-addr.arpa` and `ip6.arpa` zones sit under
  two folders, "Reverse zones (IPv4)" and "Reverse zones (IPv6)". On the
  group's Zones tab, every grouping row in the table is now collapsible
  and the `.arpa` group starts collapsed, with a zone count. Folders
  come after the forward zones in the tree, remember open or closed per
  group, and open by themselves when the selected zone is inside one. A
  zone filter holds the table's groups open. The tree and the table
  share the reverse-folder state.
