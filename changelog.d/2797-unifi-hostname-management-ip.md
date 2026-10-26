### Fixed

- **A local UniFi controller added by host name now syncs (#2797).**
  The reconciler wrote the controller's host into the controller
  Router's `management_ip`, an INET column, so a name failed the insert
  and every sync rolled back although Test connection passed. Only an IP
  literal (v4 or v6) is recorded now; a name leaves `management_ip`
  empty and stays on the controller row.
