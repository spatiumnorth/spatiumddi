### Added

- **An About page that carries the licence, the NOTICE and the
  third-party notices, for signed-in users (#2895).** The version used
  to show only in Settings, and the licence, the company and the
  notices lived only in the repository, so nothing the product serves
  carried the Apache 2.0 NOTICE text or the MIT / BSD / ISC notices
  the Vite build strips out of the bundle. `/about`, in the sidebar
  footer, now shows the product, the version, Apache-2.0 and its
  text, Spatium North, links to the source, the docs and the privacy
  statement, the full NOTICE, a note on the GPL / LGPL components of
  the OS appliance image (the Debian userland, the kernel, and
  FRRouting when the BGP advertiser is on) and where their source is,
  and two generated lists: the npm packages in the web bundle
  (`rollup-plugin-license` at `vite build`) and the Python packages
  in the API image (`pip-licenses` in the builder stage).
  **None of it is reachable without a session**, so someone probing
  the server from outside cannot learn which libraries and tools it
  runs. The page is inside the authenticated console and the sign-in
  page does not link to it. The Python list is
  `GET /api/v1/about/third-party/python`, which needs a signed-in
  user. NOTICE, LICENSE and the npm list are kept outside the web
  server's public root and served at `/legal/` only after nginx asks
  the new `GET /api/v1/about/session` whether the caller is signed
  in; both the image's nginx config and the Helm chart's TLS config
  do this, so compose, the chart and the appliance all behave the
  same. Any signed-in user may read it. `pip-licenses` is a
  build-time pin in `versions.json` and is not in the runtime image.

### Changed

- **The frontend image's build context is now the repo root.** The
  About page serves `NOTICE` and `LICENSE`, which live once at the
  root, and a file outside the context cannot be copied in. Build it
  with `docker build -f frontend/Dockerfile .`; compose, the
  Makefile, the release pipeline and the Trivy scan are updated.
