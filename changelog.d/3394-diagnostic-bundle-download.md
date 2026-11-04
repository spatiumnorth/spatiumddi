### Fixed

- Appliance → Logs & Diagnostics → Diagnostic bundle: "Download bundle" no longer lands on `{"detail":"Not authenticated"}`. It now fetches the bundle through the console's authenticated client, shows a "Building bundle…" state while it builds, saves it under the server's filename, and shows the server's reason inline if the download is refused (#3394).
