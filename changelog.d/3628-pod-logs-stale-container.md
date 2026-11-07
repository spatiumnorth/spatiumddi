### Fixed

- Fleet pod logs: choosing another pod no longer also requests it with the previous pod's container, which answered 502; the log endpoint now answers 422 / 404 instead of 502 when kubeapi rejects the container or pod (#3628).
