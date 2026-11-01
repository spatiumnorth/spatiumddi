### Fixed

- An InfluxDB export target that does not answer now says so in words ("Connection to 192.0.2.13:8086 timed out after 2s") in both the Test result and the push status, instead of "ConnectTimeout:" with nothing after the colon. The same wording now reaches the update check, webhook delivery, the Fingerbank lookup, OPNsense sync errors, DNS pool health checks, the TLD registry refresh, the upgrade pre-flight and the container list hint; only host and port are quoted, never a URL's credentials or query string.
