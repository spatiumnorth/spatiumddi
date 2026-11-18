### Fixed

- A DNS server no longer reads `ok` while a policy (RPZ) zone named could not load: the retry after a failed start verifies every zone the failed check named, renders such a policy file afresh instead of reusing it, and keeps the failure (and the quarantine) until named has loaded it (#4080).
