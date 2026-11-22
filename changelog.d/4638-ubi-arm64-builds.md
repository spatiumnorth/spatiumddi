### Fixed

- The arm64 builds of the UBI images failed: the Kea image now installs `libatomic` (Kea's arm64 binaries link it), the API image verifies PGDG's aarch64 PostgreSQL client against PGDG's separate aarch64 signing key (pinned by sha256) instead of the x86_64 one, and the BIND 9 image reads libuv's signing key from a vendored copy instead of an anonymous GitHub API call that rate-limited CI (#4638).
