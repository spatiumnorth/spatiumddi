### Fixed

- **A Helm install with `redis.auth.enabled=true` and Redis Sentinel can
  reach Redis again (#2873).** The api, worker and beat send the Redis
  password to every Sentinel they ask for the master, but the Sentinel
  configuration set no `requirepass`, so each Sentinel answered that AUTH
  with an error and no master was ever found. The chart (and
  `k8s/ha/redis-sentinel.yaml`) now renders `requirepass` and
  `sentinel sentinel-pass` into the Sentinel config when auth is on, and
  the init container's peer queries send the password too, so a
  re-created master pod still finds the current master. Installs with
  auth off are unchanged. The chart render check now covers Sentinel
  with auth enabled.
