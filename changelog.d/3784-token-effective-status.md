### Fixed
- An API token whose owner must change their password is no longer listed as "Active": the token API reports its effective `status` / `blocked_reason` (revoked, expired, owner disabled, password change required) and the Re-enable dialog no longer promises it authenticates immediately (#3784).
