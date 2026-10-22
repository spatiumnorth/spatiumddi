### Changed

- **CHANGELOG entries are fragments now, and CI runs in the merge
  queue (#2431).** A PR adds `changelog.d/<issue>-<slug>.md` instead
  of editing `CHANGELOG.md`; every PR used to insert its entry at the
  same spot under `## Unreleased`, so open PRs conflicted pairwise and
  a merge queue would drop all but one. `make changelog`
  (`scripts/changelog_assemble.py`) folds the fragments in at release
  prep and deletes them; CI validates them, and `release.yml` refuses
  a tag whose tree still carries one. `ci.yml` gains a `merge_group`
  trigger, so the nine required checks report on the queue's branch:
  the backend shards apply the PR path filter over everything the
  group's head adds to main (its merge base with main, not the event's
  `base_sha`; any doubt runs everything) and never narrow.
  A push to `main` skips the shards when the queue's run of that
  exact commit passed the full suite, and the release gate accepts
  that run as the full run of the tagged commit. Developer docs:
  `docs/DEVELOPMENT.md` §12.
