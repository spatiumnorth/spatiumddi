### Fixed

- **The Helm chart and images install on OpenShift (#3852).** On
  OpenShift (detected from the cluster, or `global.platform:
  openshift`) the chart drops the pinned `runAsUser` and `fsGroup`
  values its restricted SCC refuses, runs the frontend on :8080,
  renders a Route, and creates a minimal SCC for the DNS and DHCP
  agents only; the control plane runs under plain `restricted-v2`.
  The api, frontend, BIND9 and Kea images now also run as any uid in
  group 0; started as root or as their usual user they behave as
  before. Off OpenShift the chart's renders are byte-identical. Tested on
  OpenShift 5.0.0 (OpenShift Local); 4.22 is being verified. See `docs/deployment/KUBERNETES.md`.
