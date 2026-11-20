### Added

- **Red Hat UBI 9 image variants and a certified-image Helm profile for
  OpenShift (#3913).** The api, frontend, BIND9 and Kea images are now also
  built on `ubi9`, as `ghcr.io/spatiumnorth/<image>:<version>-ubi` and
  `:latest-ubi` (GHCR only; the Alpine / Debian images and the appliance are
  unchanged). They run as a non-root `USER`, keep the random-uid behaviour of
  the OpenShift install, and carry the same labels and `/licenses`; BIND 9.20
  and Kea are built from checksummed source because Red Hat ships neither at
  these versions. `charts/spatiumddi/values-openshift-certified.yaml` selects
  them through the new `image.tagSuffix` and runs the bundled PostgreSQL and
  Redis from Red Hat's `registry.redhat.io` images (new
  `postgresql.image.flavor` / `redis.image.flavor: rhel`, and `image.pullSecrets`
  now reaches those two pods; a Red Hat registry pull secret is required). The
  release builds each `-ubi` image on a native runner per architecture, gates it
  with Trivy and runs Red Hat's `preflight check container` (check only), and
  `trivy-gate.sh` and `lint_image_upgrades.py` understand rpm images. Nothing
  changes unless you opt in. See "OpenShift" in
  `docs/deployment/KUBERNETES.md`.
