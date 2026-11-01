### Fixed

- **Re-profile now is no longer offered to a user who cannot read the
  scan (#3271).** An IPAM Editor could start a profile scan from an
  address's detail but not read it back (`manage_nmap_scans`), so the
  button stayed on "Scanning..." until the modal closed. The button and
  the scan read now need that grant, and the section says so instead.
