### Added

- Docs: a "Join an appliance agent node to a Helm or OpenShift control plane" section in `docs/deployment/KUBERNETES.md`, with a pointer from `docs/deployment/APPLIANCE.md`. It covers the steps in order, including the two that are off by default on a Helm install (supervisor registration and the DNS / DHCP agent keys), the hostname the appliance must resolve, the 60 minute pairing code, the verification, and the first-contact certificate pinning behaviour. (#4649)
