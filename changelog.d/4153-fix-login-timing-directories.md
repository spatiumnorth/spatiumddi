### Fixed

- A refused sign-in for a name that is not a local account now does the same password-hash work whether the name has no account or a directory account, and the LDAP provider does the same number of binds for a name the directory does not know as for one it does. Sign-in time for local accounts still differs from directory-backed names when providers are configured, because local accounts are checked without contacting the providers.
