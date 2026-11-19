### Fixed

- The Red Hat UBI build of the `spatiumddi-api` image failed since PGDG published repository metadata listing a PostgreSQL 16.16 client built for RHEL 9.9 that it never uploaded. The client and its libraries are now pinned to the RHEL 9.8 build of the same release. (#4340)
