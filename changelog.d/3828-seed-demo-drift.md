### Fixed

- `scripts/seed_demo.py` works against the current API again: it enables the `network.domains` and `ipam.nat` modules, no longer sends `ddns_enabled` on the DHCP scope, matches zone names with the trailing dot (so the `corp.example.com` records are actually created), and sends SRV priority/weight/port. A missing zone is now reported as a failure. It also gains `--insecure` for self-signed control planes, a catch-all `external` DNS view, per-subnet `domain_name`, and uses `172.20.0.0/16` instead of `192.168.0.0/16` for the DMZ demo data.
