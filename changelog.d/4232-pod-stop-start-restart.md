### Fixed

- Appliance → Cluster → Pods: Stop and Start no longer answer a 500 (a pod has neither; the page now offers only Restart, and the API answers 409), and Restart works on the Helm chart's api ServiceAccount, which was granted no `delete` on pods (with `api.serviceControlRBAC.enabled`, on by default on the appliance). Restart also refuses a pod no controller owns, since deleting one would lose it for good (#4232).
