### Fixed

- Fleet pod list and pod logs no longer always answer 504 on appliances: the supervisor's kubeapi proxy now starts by default (`K8S_PROXY_ENABLED=false` opts out) and, like the other proxy loops, reaches the control plane through the in-cluster URL on a cluster member whose `CONTROL_PLANE_URL` is empty (#3618).
