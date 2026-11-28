### Fixed

- Standalone DNS / DHCP agents against an appliance control plane can now be given the certificate to trust: **Appliance → Web UI Certificate** has a Download cert button on each certificate (`GET /api/v1/appliance/tls/active/pem` and `/{id}/pem`, public certificate only), and the agent deployment docs say how to use it, how to cover the name or address agents connect to (operator, CSR or ACME certificate), and that skipping verification is lab-only (#4660).
