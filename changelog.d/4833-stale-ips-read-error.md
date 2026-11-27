### Fixed

- The Stale IPs report drew "No stale IPs in this window. Address space looks healthy." when its read failed (for example a window over 3650 days, which the server refuses with a 422); it now shows the read error through `ListEmpty` and disables "Deprecate all". (#4833)
