### Fixed

- Kea on the appliance dropped DHCP requests at the socket whenever its receive thread stalled for even a fraction of a second, because the socket took the kernel's stock 208 KiB default receive buffer (Kea never sets its own). The appliance now sets `net.core.rmem_default` and `rmem_max` to 1 MiB at boot, enough to ride out a 1 to 2 second stall without the late answers a larger buffer causes. Docker Compose and plain Kubernetes installs cannot set this from the container; the DHCP guide now says how to set it on the host. (#4544)
