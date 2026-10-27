### Fixed

- **A node that shuts down no longer leaves a pod Ready in the API
  until it is back (#2848).** The kubelet's graceful shutdown (#1976)
  stops the node's pods and then lets the shutdown go on, but it writes
  each pod's final status to the API on its own time, and k3s could
  stop before the last ones landed. A pod stopped in the shutdown's last
  seconds (on a QA cluster, a CoreDNS pod, and a database pod being
  replaced) then stayed Ready, an endpoint of its Service, until the
  node was back, and the requests sent to it failed (15 of 42 API reads
  through one node during one reboot). Once the kubelet is done, and
  before k3s stops, the node now marks NotReady each of its pods the
  API still reads Ready, as Kubernetes' node controller does for a node
  that stops reporting, and their Services drop them at once. It takes
  at most 10 s of the shutdown and never holds it.
