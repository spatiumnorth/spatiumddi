### Fixed

- The last dialogs that drew a refused save as a plain red line (DNS, IPAM, DHCP pools and scopes, VLANs, DICOM, Sites, NAT, Fleet and others) now use the announced `FormError`, so a screen reader reads the server's reason; the guard test no longer has an allowlist, so any new dialog with a plain red refusal line fails CI (#3821).
