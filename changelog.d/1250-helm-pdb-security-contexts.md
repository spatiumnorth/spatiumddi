### Changed

- **PodDisruptionBudgets and container security contexts (#1250).** The
  Helm chart and `k8s/base/` now give the api, worker and frontend a
  PodDisruptionBudget (`maxUnavailable: 1`, rendered only while more than
  one pod can run, so it never blocks a drain). Beat and the migrate Job
  run non-root with no privilege escalation and every capability
  dropped; the api and worker run non-root with the capability set
  narrowed to `NET_RAW` and `NET_BIND_SERVICE`, keeping nmap and tcpdump
  working and Pod Security `baseline` admitting the pods. The frontend,
  Kea and BIND9 are unchanged. OpenShift's uid assignment is untouched.
