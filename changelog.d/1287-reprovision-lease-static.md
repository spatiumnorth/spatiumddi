### Added

- **Re-provision a dynamic lease to a static address (#1287).** A
  device that took a dynamic lease can be moved to a permanent
  reservation in the scope's static range from the DHCP lease list
  or a lease-mirror IPAM row: the preview picks the first free
  address in the scope's reserved pools (or outside every dynamic
  pool), lists the DNS and IPAM changes, and the commit creates the
  reservation with A + PTR under the new name. A live old lease is
  left for the server to NAK at renewal; a dead one is removed with a
  Kea `lease4_del`. REST endpoints plus copilot preview / propose
  tools; Kea and IPv4 only for now.
  Based on the work of stefanriegel in #1649.
