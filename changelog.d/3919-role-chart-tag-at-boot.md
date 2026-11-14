### Fixed

- A single-node appliance slot upgrade no longer restarts the DHCP and DNS role pods a second time a few minutes after the reboot. Firstboot now writes the booted slot's image tag and chart into the role release as soon as k3s answers, so the role pods start once, on the new image (a rollback writes the old tag back). Clusters are unchanged: the supervisor still moves the shared role chart once every node runs the new version (#3919).
