### Fixed

- The IPAM to DNS auto-sync and the Sync DNS commit (subnet, block and space) no longer deadlock with a permanent DNS zone delete: they now lock the address rows they will write (ascending id) before any zone. The auto-sync also commits each subnet on its own, so a subnet that fails is rolled back alone instead of failing the whole run (#3724).
