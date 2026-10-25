### Fixed

- **A subnet's Sync > DHCP and Sync > All are no longer offered to a user the
  server refuses (#2699).** Both run the lease sync, a superadmin route; for
  an IPAM, DNS and DHCP editor they opened a dialog that ended in "Request
  failed with status code 403". The two items are now disabled with "Requires
  superadmin" (as the DHCP page's Force Sync already is), and a refusal that
  still arrives shows the server's reason.
