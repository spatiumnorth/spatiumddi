### Fixed

- **A default Helm install on k3s no longer breaks the node's own DNS (#3229).**
  The DNS and DHCP agent Services defaulted to `LoadBalancer`, which k3s's
  bundled servicelb turns into a hostPort-53 pod on every node, capturing the
  node's resolver stub so image pulls failed and the install never converged.
  They now default to `ClusterIP`; `LoadBalancer` and `NodePort` stay opt-in
  with `service.type`. **Upgrade note:** a server that never set
  `service.type` is no longer a LoadBalancer and releases its external IP, so
  set `service: { type: LoadBalancer }` (same address) on any server clients
  reach before upgrading. NOTES.txt and the chart README now say how to expose
  DNS on :53 without servicelb.
