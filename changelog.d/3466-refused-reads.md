### Fixed

- **The VRFs page, Edit VRF, the IP space dialogs and the subnet view
  ask only the reads the user may make (#3466).** A user whose role
  reads and writes VRFs and nothing else was refused `GET /asns` and
  `GET /customers` on every VRFs page load, and Edit VRF's Customer
  picker showed "None" over the VRF's linked customer. The built-in
  IPAM Editor was refused the DNS server group and zone lists when an
  IP space dialog opened, the DHCP server group list on its DHCP tab,
  and the subnet's DHCP scope list each time a subnet opened. Each
  refusal was written to the audit log as a denied read under that
  user's name. Each list is now asked only with its grant. The VRFs
  table's ASN column says "linked, not shown" instead of an ellipsis
  over the ASN's id, and the Customer, DNS and DHCP fields say a
  linked value is not visible to the role. They are disabled, so a
  save keeps the link.
