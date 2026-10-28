### Added

- **An About page that carries the licence, the NOTICE and the
  third-party notices (#2895).** The version used to show only in
  Settings, and the licence, the company and the notices lived only
  in the repository, so nothing the product serves carried the
  Apache 2.0 NOTICE text or the MIT / BSD / ISC notices the Vite
  build strips out of the bundle. `/about` now shows the product,
  the version, Apache-2.0, Spatium North, links to the source, the
  docs and the privacy statement, the full NOTICE, a note on the
  GPL / LGPL components of the OS appliance image (the Debian
  userland, the kernel, and FRRouting when the BGP advertiser is on)
  and where their source is, and links to two generated lists: the
  npm packages in the web bundle (`rollup-plugin-license` at
  `vite build`) and the Python packages in the API image
  (`pip-licenses` in the builder stage, served by the new
  unauthenticated `GET /api/v1/about/third-party/python`). It needs
  no login, since licence text has to reach anyone who is handed the
  software, including an air-gapped site. It is linked from the
  sidebar and the sign-in page. It reads only the version and the
  appliance flag the version endpoint already serves anonymously.
  `pip-licenses` is a build-time pin in `versions.json` and is not
  in the runtime image.

### Changed

- **The frontend image's build context is now the repo root.** The
  About page serves `NOTICE` and `LICENSE`, which live once at the
  root, and a file outside the context cannot be copied in. Build it
  with `docker build -f frontend/Dockerfile .`; compose, the
  Makefile, the release pipeline and the Trivy scan are updated.
