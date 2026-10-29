### Fixed

- The TLS certificate store (list, upload, generate a CSR, issue with Let's Encrypt) now has a UI on Docker Compose and Kubernetes installs, under Appliance → Fleet → TLS certificates, so DoT / DoH / DoQ certificates no longer need the API. Activating a certificate as the Web UI certificate stays appliance-only, and a certificate issued off-appliance can now be deleted (it was refused as "active" with no way to activate another).
