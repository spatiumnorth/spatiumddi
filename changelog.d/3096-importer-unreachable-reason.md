### Fixed

- The PowerDNS and Technitium importers (and the NetBox, UniFi, Tailscale, NetBird, OPNsense, Proxmox, Docker and Kubernetes connection tests) no longer end "Could not reach ...:" with nothing after the colon when the source times out; the reason now names the failure (for example `ReadTimeout (the destination timed out)`). (#3096)
