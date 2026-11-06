### Fixed

- **The Fleet tab's workloads list and restart picker work on an appliance (#3620).** The supervisor's namespace Role could not list deployments or statefulsets, nor patch any workload, so kubeapi answered 403 to both. The Role in the `spatium` namespace now grants get, list and patch on deployments, statefulsets and daemonsets, and nothing else.
