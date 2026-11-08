### Fixed

- DNS agents deployed by the Helm chart (and `k8s/dns/`) now register a host the API can resolve, so zone drift and pull-from-server work on them. The chart passes the agent a new `SERVER_HOST` (the pod's headless-Service FQDN), which registration stores as the server's host and refreshes on re-registration; the name stays the pod name. As a backstop, an agent-managed server whose host does not resolve is read at its last-seen address, with or without a DNS VIP (#3757).
