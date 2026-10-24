### Fixed

- **Walking one's own space, subnet and address no longer asks reads the
  user may not make (#2704).** The IPAM page and the address detail asked
  about a dozen reads (VRFs, Looking Glass routes, multicast groups and
  memberships, BACnet / DICOM / OT by address, DNSBL status, TLS certificates)
  the IPAM, DNS and DHCP Editors lack, each a 403 and a `denied` audit row.
  Each is now asked only with its grant. A space linked to a VRF the user may
  not read says "VRF: linked, not shown" instead of "not configured", the
  Reputation section and a zone's Certificates tab say the user may not see
  them instead of an empty answer, and the subnet BGP tab says so instead of
  "No active BGP route covers this subnet's CIDR".
