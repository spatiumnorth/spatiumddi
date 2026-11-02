### Fixed

- **Re-profile now is no longer offered to a user who cannot read the
  scan (#3271).** An IPAM Editor could start a profile scan from an
  address's detail but not read it back (`manage_nmap_scans`), so the
  button stayed on "Scanning..." until the modal closed. The button and
  the scan read now need that grant, and the section says so instead.
  A started scan whose progress cannot be read for any other reason now
  ends the "Scanning..." state and shows the error.
  With the Nmap tools module turned off, Re-profile now is gone too
  (it used to answer "Feature 'tools.nmap' is disabled."), and a stored
  profile's scan is not read; the section says scanning is turned off.
