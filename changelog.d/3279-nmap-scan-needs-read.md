### Fixed

- **"Scan with nmap" is no longer offered to a role that cannot read the
  scan (#3279).** Starting a scan takes write on `manage_nmap_scans` and
  watching it takes read, so a custom role with only write started a scan
  and then got a 403 from the viewer. The scan form, the subnet and address
  scan entries, and the address Network tab's "Scan with Nmap" button now
  need both grants (or admin) and say so when disabled. The API gates are
  unchanged.
