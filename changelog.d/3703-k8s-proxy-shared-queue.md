### Fixed

- On a multi-node control plane, reading a member appliance's pods, logs or workloads no longer always times out with a 504. The kubeapi proxy queue and its replies were held in one api process's memory, so a request queued on one api replica was never seen by the member's supervisor polling another; both now go through Redis and reach whichever replica is waiting. (#3703)
