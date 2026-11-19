### Fixed

- The Technitium agent no longer marks a zone you created by hand as its own before checking it. A zone enters the ownership ledger only once the agent has created it or it passed the ownership check, so an apply pass that aborts part-way can no longer lead the next pass to delete that zone's records (#4431).
