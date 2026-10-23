### Fixed

- **An operator TSIG key named like the group key, or differing
  only by case or a trailing dot, no longer stops the group
  (#2295).** BIND reads `foo`, `Foo` and `foo.` as one key, and
  the group's generated key is `spatium-<label>`; the API checked
  names by exact string, so either could be saved and the agent
  then rendered two `key {}` statements, which `named-checkconf`
  rejects, so the whole bundle was declined. Creating or renaming
  a key now compares names the way BIND does, refuses a clash with
  another key or the group's own key (409 / 422 naming the key),
  and reserves the `spatium-` prefix for generated keys. Keys
  already stored that clash are rendered once (the group key
  first, then operators by name) and the skip is logged, in both
  the bundle and the agent renderer.
