### Fixed

- When a source does not answer, the PowerDNS, Technitium and NetBox importers, the upgrade-image mirror check, and the Docker, Kubernetes, OPNsense, Proxmox, Tailscale and UniFi connection tests now say why, for example `ConnectTimeout (the destination timed out)`. Before, the message ended at "Could not reach ...:", and a connection test that timed out showed an empty message. The background syncs for those integrations, and for NetBird, Fortinet, PAN-OS and Meraki, report the same reason. (#3096)
