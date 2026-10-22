# Changelog fragments

Do not edit `CHANGELOG.md` in a pull request. Add one file here instead.
Every PR used to insert its entry at the same spot under `## Unreleased`,
so any two open PRs conflicted, and the merge queue removes a PR that
conflicts with the one ahead of it.

Name the file `<issue>-<slug>.md`: the issue number, then a few
lower-case words joined by hyphens, for example
`2431-merge-queue-fragments.md`. Write it exactly as the entry would read
under `## Unreleased`, starting with a `### <Section>` heading:

```markdown
### Fixed

- **One-line summary (#2431).** Body, hard-wrapped at ~70 characters
  like the rest of CHANGELOG.md.

### Migrations

- `abcdef012345` — #2431, what the migration does.
```

Sections: `Added`, `Changed`, `Deprecated`, `Removed`, `Fixed`,
`Security`, `Migrations`, `Breaking`. One fragment may use several.
Don't start a wrapped line with `#<number>`: the release-notes formatter
reads it as a heading.

CI validates every fragment (`scripts/changelog_assemble.py --check`).
At release prep, `make changelog` folds them into `## Unreleased` and
deletes them; `release.yml` refuses a tag whose tree still has any. See
`docs/DEVELOPMENT.md`, "Changelog fragments".
