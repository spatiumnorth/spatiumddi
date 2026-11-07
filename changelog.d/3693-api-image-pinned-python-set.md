### Fixed

- **The api image's Python packages are pinned, so a rebuild of one
  commit no longer ships a different set, and the health probes reuse
  one Redis connection pool (#3693).** The image installed
  `pyproject.toml`'s open ranges with no lock file, so the same commit
  built on two days carried different packages. A rebuild picked up
  redis 8.1.0 in place of 6.4.0, which showed as about 28% more api CPU
  and 27% higher p95 under load. The cost came from `/health/ready`
  building a new Redis client, and so a new connection, on every probe;
  it now reuses one pooled client, which raised its throughput per api
  CPU by about 25% on redis 6.4.0 and 60% on 8.1.0.
  `backend/requirements.txt` now pins the whole set, with redis held
  below 7; the Dockerfile and CI install through it, Dependabot bumps it
  weekly, and a test fails when the Dockerfile stops using it or the
  file stops satisfying `pyproject.toml`.
