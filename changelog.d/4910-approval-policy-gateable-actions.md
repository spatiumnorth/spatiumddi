### Fixed

- The approval policy dialog offered five actions (bulk delete, bulk edit, bulk allocate, factory reset, import commit) that the server refuses as "not gateable yet", and left out `admin`, so a block sync policy showed the wrong action. The Action list and the resource type hint now come from the server (`GET /change-requests/policies/gateable`), and the page header names only what a policy can queue (#4910).
