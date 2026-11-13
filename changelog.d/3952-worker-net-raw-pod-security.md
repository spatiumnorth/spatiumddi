### Fixed
- Helm chart: the worker pod is no longer rejected on clusters that enforce Pod Security `baseline`, such as Talos. `worker.netRawCapability` now defaults to `false`; containerd already gives the worker `NET_RAW`, so nmap scans are unchanged there. `docs/deployment/KUBERNETES.md` lists the Pod Security level each component needs (#3952).
