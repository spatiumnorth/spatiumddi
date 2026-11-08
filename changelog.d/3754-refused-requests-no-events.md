### Fixed

- A request that is refused (a permission gate, an in-handler refusal, or a sign-in that does not succeed) no longer queues a typed webhook event: only audit rows recording an action that happened are published, so a refused subnet delete no longer delivers `subnet.deleted` and a wrong password no longer delivers `auth.user.login`.
