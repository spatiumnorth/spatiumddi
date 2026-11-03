### Fixed

- **A block's and a space's subnet selection no longer offer Bulk Edit,
  Split… and Merge… to a holder the server refuses (#3384).** Like the
  subnet view's own Split… and Merge… since #1155, each stays visible and
  disabled with its reason, asking what its routes ask: write on subnets
  at the type level. A read-only user (the built-in Viewer) who ticked
  subnet rows could open all three dialogs, and the server refused each.
  The API gates are unchanged.
- **The Bulk edit subnets dialog says the server's reason (#3384).** A
  refused edit read "Request failed with status code 403"; it now carries
  the server's own words, as the Split and Merge dialogs do.
