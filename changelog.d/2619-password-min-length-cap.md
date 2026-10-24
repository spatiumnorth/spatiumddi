### Fixed

- **Password Policy: "Minimum length" no longer accepts 73 to 128** — every path that sets a password refuses one over 72 bytes (bcrypt's limit), so a minimum above 72 locked every password change out. The field and the settings API now stop at 72, and the help says why. (#2619)
