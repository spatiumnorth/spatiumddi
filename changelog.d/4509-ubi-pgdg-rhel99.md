### Fixed

- The UBI API image failed to build: PGDG removed the RHEL 9.8 build of the PostgreSQL 16.16 client that `backend/Dockerfile.ubi` fetched by URL. It now pins the RHEL 9.9 builds, which carry a different release number per architecture (`16.16-1PGDG.rhel9.9` on x86_64, `16.16-2PGDG.rhel9.9` on aarch64), and still verifies both RPMs against the pinned PGDG key.
