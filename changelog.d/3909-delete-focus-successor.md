### Fixed

- **After deleting a row from a list, keyboard focus moves to the
  next row instead of the page body (#3909).** The Delete button the
  dialog would give focus back to is removed by the refetch, so IP
  addresses, DNS records and DHCP option templates dropped focus on
  the body. The dialog now hands focus to the neighbouring row, the
  table, or the page heading when its opener is gone.
