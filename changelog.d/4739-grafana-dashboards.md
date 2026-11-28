### Added

- Importable Grafana dashboards for SpatiumDDI: an Overview, plus DNS, DHCP and IPAM views, built on the Prometheus metrics `/metrics` exposes today and using a data-source variable so they import against any Prometheus. The Helm chart can render them as ConfigMaps for the Grafana sidecar (`grafanaDashboards.enabled`, default off) (#4739).
