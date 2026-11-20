### Fixed

- The Edit dialogs of the Proxmox, Docker, Kubernetes, Meraki, UniFi, FortiGate, PAN-OS, OPNsense, NetBird, Tailscale and Cloud integrations and of a network device now read the object when they open and save only the fields you changed, so an unrelated Save no longer puts back a description, switch, IPAM space or enabled flag another client stored since the list loaded (#4370).
