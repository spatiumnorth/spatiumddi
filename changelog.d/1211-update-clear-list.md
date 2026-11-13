### Fixed

- The address, subnet and DNS record update schemas gain a documented `clear` list (`mac_address`; `gateway`; `ttl`, `priority`, `weight`, `port`), so a generated client, which cannot send an explicit `null`, can clear those fields; naming a field in `clear` while also giving it a value is a 422 (#1211).
