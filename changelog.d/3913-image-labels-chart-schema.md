### Fixed

- Every shipped image now carries the OCI and Red Hat metadata labels (name, vendor, version, release, summary, description, maintainer, url) and the project `LICENSE` and `NOTICE` under `/licenses`. The Helm chart gains a `values.schema.json`, `charts.openshift.io/*` annotations and a `helm test` hook, and the OpenShift docs state the Red Hat certification status and how to run `preflight` locally. UBI image variants and the certification submission stay open for 1.1.0 (#3913, #4020).
