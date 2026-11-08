### Fixed

- Replaced the unmaintained `python-jose` (and its `ecdsa` / `rsa` dependencies) with `joserfc` for every JWT the control plane signs and verifies (access, agent and SSO flow tokens). Tokens issued before the upgrade stay valid byte-for-byte, so nobody is logged out and no agent re-bootstraps. (#3725)
