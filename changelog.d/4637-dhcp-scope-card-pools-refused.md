### Fixed

- The subnet's DHCP Pools tab told the built-in Auditor and Compliance Editor that every scope had "0 pools" and "Pools (0)", because both roles could read DHCP scopes but not pools and the card drew the refused pool list as empty. Both roles now also get `read` on DHCP pools (existing installs pick it up at the next restart, which refreshes built-in role permissions), so the tab shows the real count. A custom role that can read scopes but not pools now sees the card say it may not see the pools, with no count, instead of "0 pools". (#4637)
