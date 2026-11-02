### Fixed

- Fleet's "Service lifecycle apply failed" no longer sticks forever after an approved-again node's forced role apply fails (for example `kubeapi /readyz not ok` just after a k3s restart): the supervisor now retries on the next heartbeat instead of skipping it as "env unchanged" (#3285).
