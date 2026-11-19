### Fixed

- A new default-on `database_size_high` alert warns when the database passes a size you set (50 GiB by default, critical at 1.5 times it), and Platform Insights → Postgres gains a Data retention table showing each pruned table's size, estimated rows, governing retention window and oldest row; the Copilot gets a matching read-only `find_data_retention` tool (#2274).
