### Fixed

- **A new Web UI certificate no longer closes the web ports node by node
  (#1173).** Every certificate change rolled the frontend Deployment:
  activating an uploaded, CSR-signed or Let's Encrypt certificate, and the
  self-signed re-mint a control-plane join makes. On a multi-node control
  plane that roll is terminate-first (hostNetwork, host ports 80/443), so
  each node refused connections on :80 and :443 until its new frontend pod
  started, about 23 s on the seed during a join. The frontend image now
  reloads nginx in place when the kubelet updates its mounted certificate,
  and the api no longer rolls the frontend. A reload keeps the ports open,
  and each node serves the new certificate within about 90 s.
