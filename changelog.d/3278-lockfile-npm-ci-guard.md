### Fixed

- The frontend lockfile again carries the `picomatch` entry that `npm ci` on node 22 needs: a Dependabot group update dropped it after #3280 added it. CI's Frontend Lint job now runs `npm ci --dry-run`, so a lockfile out of sync with `package.json` fails CI instead of being repaired silently by `npm install` (#3278).
