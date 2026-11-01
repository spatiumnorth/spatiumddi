### Fixed

- **"Scan with nmap" is no longer offered to a role that cannot read the
  scan (#3279).** Starting a scan takes write on `manage_nmap_scans` and
  watching it takes read, so a custom role with only write started a scan
  and then got a 403 from the viewer. The scan form, the subnet Tools menu,
  and the "Scan with Nmap" buttons on the IP detail and Edit address dialogs
  now need both grants (or admin) and say so when disabled. A Copilot nmap
  scan proposal run by such a role now says its progress cannot be shown,
  instead of polling a 403 behind a "Loading scan…" spinner. The API gates
  are unchanged.
