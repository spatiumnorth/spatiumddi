### Fixed

- The IPAM to DNS auto-sync no longer deadlocks with a permanent DNS zone delete: each subnet's DDNS re-apply and drift sync now lock their address rows (ascending id) and zones before writing, and commit per subnet, so a zone delete is no longer answered with a 500 (#3724).
