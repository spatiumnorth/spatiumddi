### Fixed

- **A subnet page no longer offers Sync > DNS or the Edit dialog's Delete to a holder who cannot use them (#2571).** Both stay visible and disabled with their reason, asking what their routes ask: DNS sync needs read in IPAM and write on subnets, Delete needs delete on subnets, both at the type level (a grant scoped to one subnet reaches neither).
