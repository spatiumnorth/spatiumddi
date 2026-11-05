### Fixed

- A Docker, FortiGate, PAN-OS, Meraki, Proxmox, UniFi, OPNsense or Cloud sync no longer rewrites every mirrored subnet that has a gateway when nothing changed upstream. The gateway was compared as a string against the stored address, so each sync moved the subnet's modified time and counted it as updated.
- An Azure cloud sync no longer rewrites every mirrored VM address on each run. Azure reports MACs as `00-0D-3A-…`, which never matched the stored `00:0d:3a:…`, so each sync counted every VM address as updated.
