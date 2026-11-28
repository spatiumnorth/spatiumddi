### Added

- A read-only VMware vSphere integration (off by default, enable the `integrations.vsphere` module) mirrors powered-on VM guest addresses (read through VMware Tools) and ESXi hosts named by IP from vCenter 7.0 Update 2 or later into IPAM, over the vSphere Automation REST API. It fills subnets you already have, keeps a VM's rows while its VMware Tools is not running, deletes nothing after an incomplete read, and appears on both dashboard surfaces; the migration is `a7d3f9c1e268` (#4740)
