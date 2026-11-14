### Fixed

- A read-only user no longer sees a subnet's Reconcile **Discover now** and an overlay's **Run simulation** drawn enabled: both routes need write, so each is now disabled with the permission it needs, and a refused press shows the server's own reason instead of "Failed to queue the sweep." or "Simulation failed" (#4117, #4118).
