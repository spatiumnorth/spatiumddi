### Fixed

- **The IPAM address search no longer offers Bulk edit to a holder the
  server refuses (#3423).** Like the Delete beside it, Bulk edit stays
  visible and disabled with its reason unless the caller holds what
  `POST /ipam/addresses/bulk-edit` asks: write on subnets, or a write
  grant on an address set (#103). A read-only user (the built-in Viewer)
  who ticked a match could open the dialog, and the server refused the
  edit. The API gate is unchanged.
