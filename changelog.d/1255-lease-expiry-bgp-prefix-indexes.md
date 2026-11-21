### Fixed

- Added a partial index for the DHCP lease-expiry sweep (`state = 'active'` by `expires_at`) and a GiST index on the BGP Looking Glass route prefix, so the sweep and the route containment queries (hijack-coverage alert, reachability, prefix filter) stop scanning whole tables (#1255).
