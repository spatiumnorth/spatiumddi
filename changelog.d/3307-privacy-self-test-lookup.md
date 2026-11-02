### Fixed

- `docs/PRIVACY.md` now lists the appliance self-test's DNS lookup of `registry-1.docker.io` (on demand only, a name query through the host resolver, no connection to Docker Hub), the outbound-host CI guard also catches bare hostnames passed to resolve and connect calls, and the self-test endpoint no longer blocks the API event loop (#3307).
