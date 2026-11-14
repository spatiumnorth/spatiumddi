### Fixed

- A single-node appliance slot upgrade no longer restarts the DHCP and DNS role pods a second time after the reboot. As soon as the Kubernetes API answers, firstboot moves the role DaemonSets, then the role chart, onto the booted slot's image tag, before the kubelet restarts the old pods, so the role pods start once, on the new image (a rollback writes the old tag back). Clusters are unchanged: the supervisor still moves the shared role chart once every node runs the new version (#3919).
