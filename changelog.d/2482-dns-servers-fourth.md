### Fixed

- **Edit DHCP Scope no longer drops a fourth DNS server (#2482).**
  Leaving the DNS Servers field cut its list to three while the input
  still showed four, so a Save lost the fourth. The list is no longer
  capped by the editor.
