### Fixed

- Appliance: the "Control plane not converged" flag in Fleet is now cleared once the api converges. A steady reboot that finds the flag waits up to five minutes for the api to come back on the slot's image and removes the flag when it does (the flag stays if it does not, and the boot never fails). The wait for the control chart before a trial slot is committed is now measured against the clock, so "Waiting up to 900s" is 900 s and the unit keeps its margin. A stale comment about how long finished migrate Jobs are kept is corrected (#4749).
