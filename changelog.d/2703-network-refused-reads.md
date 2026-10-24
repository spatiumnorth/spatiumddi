### Fixed

- **The network registries no longer say "empty" over a read the server
  refused (#2703).** E911, AV, BACnet, DICOM, OT and the multicast Domains
  tab showed "No ... yet", "0 flows" / "0 devices" / "0 AEs" to a user who
  may not read them, and Providers asked `GET /asns` on every visit and
  showed a stored Default ASN as a bare dash. Each now says the user may not
  see the list, and Providers does not ask for ASNs without read on
  `manage_asns`, showing the Default ASN as set but hidden.
