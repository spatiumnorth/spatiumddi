### Fixed

- The TLS certificate store (list, upload, generate a CSR, issue with Let's Encrypt) now has a UI on Docker Compose and Kubernetes installs, under Appliance → Fleet → TLS certificates, so DoT / DoH / DoQ certificates no longer need the API. Activating a certificate as the Web UI certificate stays appliance-only, and a certificate issued off-appliance can now be deleted (it was refused as "active" with no way to activate another).
- A Let's Encrypt certificate a DNS group serves for DoT / DoH / DoQ is now auto-renewed, and renewed in place. Renewal used to cover only the active Web UI certificate and landed in a new certificate, so the DNS group kept serving the old one until it expired; on an appliance, renewing a DoT certificate could also make it the Web UI certificate.
- Deleting a certificate a DoQ-only DNS group serves is now refused like DoT and DoH; it used to go through and leave the listener with no certificate.
- The ACME HTTP-01 challenge is now proxied by the frontend on Docker Compose and Helm installs too; it used to fall through to the web UI's index page, so HTTP-01 orders could not complete there.
- On Docker Compose and Kubernetes, the API-token enrolment QR no longer carries the fingerprint of a stored certificate this install does not serve.
