### Fixed

- **A demote to one node no longer turns the API away for over three
  minutes (#2878).** Demoting both members of a three-node cluster
  restarts the one PostgreSQL instance left, because its memory limit
  follows the control-plane size. With no replica to switch to, its
  smart shutdown refused every new database connection for
  CloudNativePG's default 180 s while the services' pooled sessions
  held it, so the api's new pod could not start and every request
  answered 502 meanwhile. The PostgreSQL Cluster now sets
  `smartShutdownTimeout: 15` at every size: an instance restarted in
  place falls back to a fast shutdown after 15 s. The field is not part
  of the instance pods' spec, so upgrading into this restarts nothing.
