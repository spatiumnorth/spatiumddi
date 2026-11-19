### Fixed

- CI: every third-party GitHub Action is now pinned to an immutable commit (with the release tag in a trailing comment) so a moved tag cannot change what CI runs, `build-appliance.yml` and `build-appliance-builder.yml` gain a read-only top-level token ceiling, a weekly OpenSSF Scorecard workflow publishes to the code scanning tab and the README badge, and `scripts/lint_action_pins.py` keeps the set from regrowing (#1334).
