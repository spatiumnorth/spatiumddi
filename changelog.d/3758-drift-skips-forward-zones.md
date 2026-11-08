### Fixed

- DNS zone drift, Sync with Servers and the scheduled pull no longer attempt a zone transfer of forward and stub zones, which a server does not hold authoritatively. Drift reports them as "Not applicable" with a reason instead of a failed pull (NOTAUTH), and the group-level sync and scheduled pull skip them.
