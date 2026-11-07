### Fixed

- **A subnet, block or space delete's approval preview counts the
  address records it retracts (#3536).** Deleting a subnet, block or
  space also takes out of service, into the same batch, the A, AAAA
  and PTR records of its addresses that live in zones that stay (a
  forward zone, or a reverse zone a sibling subnet keeps). The
  two-person approval preview never counted them, so the approver was
  not told that those names stop resolving, and an address added
  between the request and the approval did not refuse the approval.
  The preview now counts them with the batch's DNS records, chosen as
  the delete chooses them, so an address added in between refuses the
  approval as a change in any other count does. Lease and reservation
  mirrors are left out: they go with their DHCP scope before the
  delete, and their records with them.
