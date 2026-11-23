### Fixed

- An appliance assigned a DNS or DHCP role while the control plane has no agent key for it now says so: the supervisor reports the held-back roles in its heartbeat, and the Fleet row marks them "needs key" while the appliance drilldown shows a warning naming the missing agent key and how to set it. Before, the node started nothing and the row looked healthy (#4646).
