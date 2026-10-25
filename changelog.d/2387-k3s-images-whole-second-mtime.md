### Fixed

- **`spatium-k3s-images verify --repair` no longer makes k3s re-import the
  repaired tarballs on every boot (#2387).** The repair moved a tarball's
  mtime to `time.time()`, fraction and all, while k3s records the
  import's modTime to the second and re-imports a file whose mtime is
  After it, so each boot re-imported it and rewrote the same entry. The
  repair now stamps a whole second, and `imported()` compares exactly
  like k3s, so `verify` no longer reports "imported" for a file k3s will
  import again.
