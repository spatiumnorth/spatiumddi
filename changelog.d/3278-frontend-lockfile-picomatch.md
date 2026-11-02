### Fixed

- The frontend lockfile now carries the `picomatch` 4.x entry that `package.json` implies, so `npm ci` succeeds with the npm bundled in Node 22 instead of failing with "Missing: picomatch@4.0.7 from lock file" (#3278).
