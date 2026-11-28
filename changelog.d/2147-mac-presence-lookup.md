### Added

- `POST /api/v1/presence` looks up device presence for up to 500 MAC addresses at once, in any common format. Each MAC reports whether it is present (an active lease plus recent activity within a configurable window), its lease IP, hostname and expiry, the freshest activity signal, a randomized-MAC flag, and how stale polled Windows DHCP data can be. Results only cover subnets the caller may read, and anything in the Trash is never reported. The Operator Copilot has the same lookup as `find_device_presence`. (#2147)
