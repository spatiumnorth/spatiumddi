### Fixed

- The api and the frontend now work on IPv6-only Kubernetes clusters, and still on IPv4-only and dual-stack ones. The api used to bind only `0.0.0.0`, and the frontend listened on IPv4 only and resolved the api with `ipv6=off`, so on a cluster with no IPv4 pod addresses the probes, the Service and every `/api` request failed. The api now binds every address family the container has (set `API_BIND_HOST` to pin one address), and the frontend adds the IPv6 listener and lets nginx resolve AAAA records whenever the container has IPv6 (`SPATIUM_FRONTEND_IPV6=on|off` forces it).
