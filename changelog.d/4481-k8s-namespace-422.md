### Fixed

- The appliance pod list, pod log, workload list and rollout-restart routes now answer 422 naming `spatium` as the only served namespace when asked for another (such as `kube-system`), instead of a 502 "kubeapi returned 403" for a request the kubeapi never received; the pod list description no longer offers other namespaces.
