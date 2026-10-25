### Fixed

- **A disabled device policy's preview no longer says its manual match is "in force" (#2753).**
  The preview warned that a manual match expression "is in force" whatever
  the policy's Enabled state, beside "Renders no". A disabled policy is not
  in the rendered Kea configuration at all. For a disabled policy the
  warning now says the expression is not applied until the policy is
  enabled; an enabled policy's warning is unchanged.
