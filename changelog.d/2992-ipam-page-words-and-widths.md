### Fixed

- **Clean Orphans says why when the server refuses the purge (#2992).**
  A purge refused with 404 (the subnet went to the Trash meanwhile), 403
  or 502 left the dialog as it was, with no message. The dialog now shows
  the server's reason.
- **The IPAM tree keeps a subnet's CIDR whole (#2993).** A subnet row
  gave its CIDR only the room its name and the customer, site and BGP
  chips left, so it could be cut or vanish. As on a block row (#2822),
  the CIDR never shrinks and the name is cut instead.
- **The IPAM tree says when its quick-filter matches nothing (#2994).**
  The pane went blank under "IP Spaces". It now says that nothing
  matches the filter, with a link to clear it.
