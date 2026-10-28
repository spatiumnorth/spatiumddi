### Fixed

- **`/health/ready` no longer waits on the saturated request pool, and the
  api now has a graceful-shutdown timeout (#2944).** Under about 90
  concurrent bulk writes the readiness probe's `SELECT 1` (and the schema
  check) queued behind request traffic for a pooled connection, passed its
  4 s bound and logged `readiness_check_failed`, which could take a busy but
  healthy pod out of the Service. The probe now has its own one-connection
  engine, disposed at shutdown; a database that is really down still fails
  it and the schema-at-head semantics are unchanged. Separately, uvicorn ran
  with no graceful-shutdown timeout, so a request started just before a stop
  could outlast the grace period and the kill landed before lifespan shutdown
  disposed the after-commit hooks' engine. The api image now passes
  `--timeout-graceful-shutdown 20`, below the 30 s
  `terminationGracePeriodSeconds` in `k8s/base` and the Helm chart; the
  compose files set `stop_grace_period: 30s` on the api (Docker's default is
  10 s).
  The probe's connection is held open at idle, so each api pod now counts
  one more Postgres connection. The appliance's connection budget counts it
  (`postgres_connection_budget` and firstboot's mirror): the cluster can open
  52 connections at one node, 134 at three and 227 at nine, and on a
  multi-node appliance whose Postgres memory limit is sized from that budget
  the limit rises by about 16 MiB per control-plane node (3019Mi at three
  nodes on a 12 GiB seed, 4507Mi at nine), which CloudNativePG applies with
  one rolling restart. `max_connections` now passes the chart's 200 from
  seven nodes with two worker processes (was eight).
  The frontend nginx now rate limits `/health/*` and `/metrics` per client,
  5 requests a second with a burst of 20, answering 429 past it, in both the
  image template and the chart's TLS config. `/health/ready` and
  `/health/platform` are unauthenticated, and a flood through the frontend
  could otherwise queue the probe's one database connection. The client is
  the address after `FRONTEND_TRUSTED_PROXY_CIDRS` resolution, so behind an
  unlisted proxy every client shares one allowance. The kubelet probes the
  api pod directly and is not affected; the dashboard polls
  `/health/platform` every 30 s.
