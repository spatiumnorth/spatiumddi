### Fixed

- **A network device's, ASN's, overlay's and VRF's own page no longer
  offers a read-only user writes the server refuses (#2518).** Test
  Connection, Poll Now, Edit and Delete on a device, the device list's
  Active switch, an ASN's refreshes and its peering and community
  actions, an overlay's site and policy actions, and a VRF's Edit are
  now disabled with their reason, as on the list pages. A refused Poll
  Now, Detach or policy change shows the server's reason.
