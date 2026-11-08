### Fixed

- A request that is refused (a permission gate or an in-handler refusal) no longer queues a typed webhook event: only audit rows recording an action that happened are published, so a refused subnet delete no longer delivers `subnet.deleted`.
